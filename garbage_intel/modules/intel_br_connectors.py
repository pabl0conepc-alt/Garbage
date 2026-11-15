"""Brazilian registry numbers, phone numbers and places.

* **CNPJ** (company registry): validated offline (check digits, head office or
  branch), then looked up in the public Receita Federal data published by
  BrasilAPI and Minha Receita: legal and trade names, status, activity,
  address, size, capital. Partners are people, so only how many there are
  and their roles are kept, never their names.
* **CPF** (individual taxpayer number): offline only. Whether the check digits
  are valid and which fiscal region issued it. Who it belongs to is never
  looked up: that is a personal-data search and is out of scope.
* **Phone numbers**: offline only. Country by calling code; for Brazil the area
  code (DDD) and its state, and whether it is mobile, landline or
  non-geographic. The owner is never looked up. Area codes say where a number
  was issued, not where anyone is.
* **Places**: an address or coordinates, geocoded with OpenStreetMap
  Nominatim within its usage policy (identified client, one request per
  second at most, results cached for a month).
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable
from urllib.parse import urlencode

from .. import __version__, net
from ..intel import Connector, ConnectorContext, Finding, register_connector
from ..net import FetchResult, NetworkError

FETCH: Callable[..., FetchResult] = net.fetch
USER_AGENT = f"GARBAGE-workstation/{__version__} (local investigation tool)"
BRASILAPI = "https://brasilapi.com.br/api/cnpj/v1/"
MINHA_RECEITA = "https://minhareceita.org/"
NOMINATIM = "https://nominatim.openstreetmap.org/"

# --------------------------------------------------------------------------
# Detection


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def cpf_check_digits(first_nine: str) -> str:
    """The two check digits a CPF with these first nine digits must end in."""
    digits = first_nine
    for size in (9, 10):
        total = sum(int(digits[index]) * (size + 1 - index) for index in range(size))
        digits += str((total * 10) % 11 % 10)
    return digits[9:]


def cpf_valid(digits: str) -> bool:
    if len(digits) != 11 or len(set(digits)) == 1:
        return False
    for size in (9, 10):
        total = sum(int(digits[index]) * (size + 1 - index) for index in range(size))
        check = (total * 10) % 11 % 10
        if check != int(digits[size]):
            return False
    return True


def cnpj_valid(digits: str) -> bool:
    if len(digits) != 14 or len(set(digits)) == 1:
        return False
    weights = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    for size in (12, 13):
        factors = weights if size == 12 else [6, *weights]
        total = sum(int(digits[index]) * factors[index] for index in range(size))
        remainder = total % 11
        check = 0 if remainder < 2 else 11 - remainder
        if check != int(digits[size]):
            return False
    return True


_CPF_FORMAT = re.compile(r"\d{3}\.\d{3}\.\d{3}-\d{2}")
_CNPJ_FORMAT = re.compile(r"\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}")
_PHONE_CHARS = re.compile(r"\+?[\d\s().-]{8,24}")
_COORDINATES = re.compile(r"(-?\d{1,2}(?:\.\d+)?)\s*[,;\s]\s*(-?\d{1,3}(?:\.\d+)?)")
PREFIX = re.compile(r"^(cpf|cnpj|tel|telefone|phone|local|lugar|endere[cç]o|place)\s*:\s*", re.IGNORECASE)


def detect(raw: str) -> dict[str, str] | None:
    """The Brazilian document, phone or place this value is, or None."""
    value = raw.strip()
    forced = ""
    prefix = PREFIX.match(value)
    if prefix:
        forced = prefix.group(1).lower()
        value = value[prefix.end():].strip()
    digits = _digits(value)
    if forced == "cpf" or (not forced and (_CPF_FORMAT.fullmatch(value) or (value.isdigit() and len(value) == 11 and cpf_valid(value)))):
        if len(digits) == 11:
            return {"type": "cpf", "value": digits, "label": "CPF"}
    if forced == "cnpj" or (not forced and _CNPJ_FORMAT.fullmatch(value) and cnpj_valid(digits)):
        if len(digits) == 14:
            return {"type": "cnpj", "value": digits, "label": "CNPJ"}
    if forced in ("tel", "telefone", "phone") or (not forced and _PHONE_CHARS.fullmatch(value) and _looks_like_phone(value)):
        phone = parse_phone(value)
        if phone:
            return {"type": "phone", "value": phone["e164"], "label": "Telefone"}
    coordinates = _COORDINATES.fullmatch(value)
    if coordinates and (forced in ("", "local", "lugar", "place") or forced.startswith("endere")):
        latitude, longitude = float(coordinates.group(1)), float(coordinates.group(2))
        if -90 <= latitude <= 90 and -180 <= longitude <= 180 and ("." in coordinates.group(1) or forced):
            return {"type": "location", "value": f"{latitude:.6f},{longitude:.6f}", "label": "Coordenadas"}
    if forced in ("local", "lugar", "place") or forced.startswith("endere"):
        if 3 <= len(value) <= 200:
            return {"type": "location", "value": " ".join(value.split()), "label": "Endereço"}
    return None


def looks_like_address(value: str) -> bool:
    """Free text that reads like an address: geocode it as a place."""
    text = value.strip()
    return (
        3 <= len(text) <= 200
        and any(character.isalpha() for character in text)
        # A number or a comma, as in "Rua X, 123" or "Paris, França": plain
        # words alone need the "local:" prefix, so typos are not geocoded.
        and ("," in text or any(character.isdigit() for character in text))
        and "@" not in text
        and "://" not in text
    )


def _looks_like_phone(value: str) -> bool:
    digits = _digits(value)
    if value.startswith("+"):
        return 8 <= len(digits) <= 15
    # Brazilian national formats: (11) 98765-4321, 11 3456-7890, 0800 123 4567.
    return len(digits) in (10, 11) or (len(digits) == 11 and digits.startswith("0800"))


# --------------------------------------------------------------------------
# Phone numbers (offline)

COUNTRY_CODES = {
    "1": "EUA, Canadá e Caribe", "7": "Rússia ou Cazaquistão", "20": "Egito", "27": "África do Sul", "30": "Grécia",
    "31": "Países Baixos", "32": "Bélgica", "33": "França", "34": "Espanha", "36": "Hungria", "39": "Itália",
    "40": "Romênia", "41": "Suíça", "43": "Áustria", "44": "Reino Unido", "45": "Dinamarca", "46": "Suécia",
    "47": "Noruega", "48": "Polônia", "49": "Alemanha", "51": "Peru", "52": "México", "53": "Cuba",
    "54": "Argentina", "55": "Brasil", "56": "Chile", "57": "Colômbia", "58": "Venezuela", "60": "Malásia",
    "61": "Austrália", "62": "Indonésia", "63": "Filipinas", "64": "Nova Zelândia", "65": "Singapura",
    "66": "Tailândia", "81": "Japão", "82": "Coreia do Sul", "84": "Vietnã", "86": "China", "90": "Turquia",
    "91": "Índia", "92": "Paquistão", "93": "Afeganistão", "94": "Sri Lanka", "95": "Mianmar", "98": "Irã",
    "212": "Marrocos", "213": "Argélia", "216": "Tunísia", "218": "Líbia", "234": "Nigéria", "244": "Angola",
    "245": "Guiné-Bissau", "238": "Cabo Verde", "239": "São Tomé e Príncipe", "254": "Quênia", "258": "Moçambique",
    "351": "Portugal", "352": "Luxemburgo", "353": "Irlanda", "354": "Islândia", "358": "Finlândia",
    "370": "Lituânia", "371": "Letônia", "372": "Estônia", "380": "Ucrânia", "385": "Croácia",
    "420": "Tchéquia", "421": "Eslováquia", "591": "Bolívia", "593": "Equador", "595": "Paraguai",
    "597": "Suriname", "598": "Uruguai", "670": "Timor-Leste", "852": "Hong Kong", "853": "Macau",
    "886": "Taiwan", "966": "Arábia Saudita", "971": "Emirados Árabes Unidos", "972": "Israel", "974": "Catar",
}

DDD = {
    "11": ("SP", "São Paulo e região metropolitana"), "12": ("SP", "São José dos Campos e Vale do Paraíba"),
    "13": ("SP", "Santos e Baixada Santista"), "14": ("SP", "Bauru e Marília"), "15": ("SP", "Sorocaba"),
    "16": ("SP", "Ribeirão Preto e Araraquara"), "17": ("SP", "São José do Rio Preto"), "18": ("SP", "Presidente Prudente"),
    "19": ("SP", "Campinas e Piracicaba"), "21": ("RJ", "Rio de Janeiro e região metropolitana"),
    "22": ("RJ", "Campos dos Goytacazes e Região dos Lagos"), "24": ("RJ", "Volta Redonda e Petrópolis"),
    "27": ("ES", "Vitória"), "28": ("ES", "Cachoeiro de Itapemirim"), "31": ("MG", "Belo Horizonte"),
    "32": ("MG", "Juiz de Fora"), "33": ("MG", "Governador Valadares"), "34": ("MG", "Uberlândia e Triângulo Mineiro"),
    "35": ("MG", "Poços de Caldas e Sul de Minas"), "37": ("MG", "Divinópolis"), "38": ("MG", "Montes Claros"),
    "41": ("PR", "Curitiba"), "42": ("PR", "Ponta Grossa"), "43": ("PR", "Londrina"), "44": ("PR", "Maringá"),
    "45": ("PR", "Cascavel e Foz do Iguaçu"), "46": ("PR", "Francisco Beltrão e Pato Branco"),
    "47": ("SC", "Joinville, Blumenau e Itajaí"), "48": ("SC", "Florianópolis e Criciúma"), "49": ("SC", "Chapecó e Lages"),
    "51": ("RS", "Porto Alegre"), "53": ("RS", "Pelotas"), "54": ("RS", "Caxias do Sul"), "55": ("RS", "Santa Maria"),
    "61": ("DF", "Brasília e entorno"), "62": ("GO", "Goiânia"), "63": ("TO", "Palmas"), "64": ("GO", "Rio Verde"),
    "65": ("MT", "Cuiabá"), "66": ("MT", "Rondonópolis e Sinop"), "67": ("MS", "Campo Grande"), "68": ("AC", "Rio Branco"),
    "69": ("RO", "Porto Velho"), "71": ("BA", "Salvador"), "73": ("BA", "Ilhéus e Itabuna"), "74": ("BA", "Juazeiro"),
    "75": ("BA", "Feira de Santana"), "77": ("BA", "Vitória da Conquista e Barreiras"), "79": ("SE", "Aracaju"),
    "81": ("PE", "Recife"), "82": ("AL", "Maceió"), "83": ("PB", "João Pessoa"), "84": ("RN", "Natal"),
    "85": ("CE", "Fortaleza"), "86": ("PI", "Teresina"), "87": ("PE", "Petrolina e Sertão"), "88": ("CE", "Juazeiro do Norte"),
    "89": ("PI", "Picos e Floriano"), "91": ("PA", "Belém"), "92": ("AM", "Manaus"), "93": ("PA", "Santarém"),
    "94": ("PA", "Marabá"), "95": ("RR", "Boa Vista"), "96": ("AP", "Macapá"), "97": ("AM", "interior do Amazonas"),
    "98": ("MA", "São Luís"), "99": ("MA", "Imperatriz"),
}
NON_GEOGRAPHIC = ("0800", "0300", "0303", "0500", "0900", "3003", "3004", "4002", "4003", "4004", "4007", "4020")
SERVICE_MEANING = {
    "0800": "ligação gratuita para quem liga; usado por empresas e serviços de atendimento",
    "0300": "custo compartilhado: quem liga paga como ligação local",
    "0303": "prefixo que a Anatel exige para telemarketing ativo",
    "0500": "ligações de doação para entidades",
    "0900": "serviço com tarifa adicional (cobrança acima da ligação comum)",
}
UNIQUE_NATIONAL = "número único nacional de empresa: o mesmo em todo o país, discado sem DDD"
STATE_NAMES = {
    "AC": "Acre", "AL": "Alagoas", "AM": "Amazonas", "AP": "Amapá", "BA": "Bahia", "CE": "Ceará", "DF": "Distrito Federal",
    "ES": "Espírito Santo", "GO": "Goiás", "MA": "Maranhão", "MG": "Minas Gerais", "MS": "Mato Grosso do Sul",
    "MT": "Mato Grosso", "PA": "Pará", "PB": "Paraíba", "PE": "Pernambuco", "PI": "Piauí", "PR": "Paraná",
    "RJ": "Rio de Janeiro", "RN": "Rio Grande do Norte", "RO": "Rondônia", "RR": "Roraima", "RS": "Rio Grande do Sul",
    "SC": "Santa Catarina", "SE": "Sergipe", "SP": "São Paulo", "TO": "Tocantins",
}
# The DDD that covers each state capital.
CAPITAL_DDD = {
    "SP": "11", "RJ": "21", "ES": "27", "MG": "31", "PR": "41", "SC": "48", "RS": "51", "DF": "61", "GO": "62",
    "TO": "63", "MT": "65", "MS": "67", "AC": "68", "RO": "69", "BA": "71", "SE": "79", "PE": "81", "AL": "82",
    "PB": "83", "RN": "84", "CE": "85", "PI": "86", "PA": "91", "AM": "92", "RR": "95", "AP": "96", "MA": "98",
}


def parse_phone(raw: str) -> dict[str, Any] | None:
    text = raw.strip()
    digits = _digits(text)
    if text.startswith("+") or (text.startswith("00") and len(digits) > 11):
        digits = digits[2:] if text.startswith("00") else digits
        code = next((digits[:size] for size in (3, 2, 1) if digits[:size] in COUNTRY_CODES), "")
        if not code or not 7 <= len(digits) - len(code) <= 13:
            return None
        national = digits[len(code):]
    else:
        code, national = "55", digits
        if national.startswith("0") and national[:4] not in NON_GEOGRAPHIC and len(national) in (11, 12):
            national = national[1:]  # trunk prefix "0" before the area code
    result: dict[str, Any] = {
        "e164": f"+{code}{national}",
        "country_code": code,
        "country": COUNTRY_CODES.get(code, ""),
        "national": national,
    }
    if code != "55":
        return {
            **result,
            "formats": [("E.164 (sistemas e apps)", result["e164"]), ("Discando do Brasil", f"00 + operadora + {code} {national}")],
        }
    if national[:4] in NON_GEOGRAPHIC:
        prefix = national[:4]
        rest = national[4:]
        formatted = f"{prefix} {rest[:3]} {rest[3:]}".strip() if prefix.startswith("0") else f"{prefix}-{rest}"
        return {
            **result,
            "line_type": "não geográfico",
            "service": prefix,
            "service_meaning": f"{SERVICE_MEANING.get(prefix, UNIQUE_NATIONAL)}. Só funciona discado de dentro do Brasil",
            "formatted": formatted,
            "formats": [("Como aparece", formatted), ("Só dígitos", national)],
        }
    area, subscriber = national[:2], national[2:]
    if area not in DDD or len(subscriber) not in (8, 9):
        return None
    if len(subscriber) == 9 and not subscriber.startswith("9"):
        return None
    old_mobile = len(subscriber) == 8 and subscriber[0] in "6789"
    line_type = "celular" if len(subscriber) == 9 else ("fixo" if subscriber[0] in "2345" else "celular sem o 9 (formato antigo)")
    state, region = DDD[area]
    local = f"{subscriber[:-4]}-{subscriber[-4:]}"
    formatted = f"+55 ({area}) {local}"
    return {
        **result,
        "ddd": area,
        "state": state,
        "state_name": STATE_NAMES.get(state, state),
        "region": region,
        "capital": CAPITAL_DDD.get(state) == area,
        "state_ddds": [code for code, (uf, _) in DDD.items() if uf == state and code != area],
        "line_type": line_type,
        "old_mobile": old_mobile,
        "suggestion": f"+55 ({area}) 9{local}" if old_mobile else "",
        "formatted": formatted,
        "formats": [
            ("Nacional", f"({area}) {local}"),
            ("Internacional", f"+55 {area} {subscriber[:-4]} {subscriber[-4:]}"),
            ("E.164 (sistemas e apps)", f"+55{national}"),
            ("De outro DDD no Brasil", f"0 + operadora + {area} {local}"),
            ("Do exterior", f"00 55 {area} {subscriber[:-4]} {subscriber[-4:]}"),
            ("Só dígitos", national),
            ("Link tel:", f"tel:+55{national}"),
        ],
    }


# --------------------------------------------------------------------------
# Offline connector: CPF, CNPJ and phone facts

CPF_REGIONS = {
    "0": "RS", "1": "DF, GO, MS, MT e TO", "2": "AC, AM, AP, PA, RO e RR", "3": "CE, MA e PI",
    "4": "AL, PB, PE e RN", "5": "BA e SE", "6": "MG", "7": "ES e RJ", "8": "SP", "9": "PR e SC",
}


def _documents_connector(context: ConnectorContext) -> list[Finding]:
    value = context.query_value
    if context.query_type == "cpf":
        valid = cpf_valid(value)
        formatted = f"{value[:3]}.{value[3:6]}.{value[6:9]}-{value[9:]}"
        findings = [
            Finding("formatted", formatted, {}),
            Finding("validity", "válido" if valid else "inválido", {"meaning": "Só os dígitos verificadores; não diz se o CPF existe nem a quem pertence."}),
        ]
        if len(set(value)) == 1:
            findings.append(Finding("warning", "todos os dígitos iguais", {"meaning": "Inválido por regra da Receita; aparece em testes e cadastros falsos."}))
        else:
            expected = cpf_check_digits(value[:9])
            findings.append(
                Finding(
                    "check-digits",
                    f"{value[9:]} conferem" if valid else f"{value[9:]} não conferem; o certo seria {expected}",
                    {"expected": expected, "meaning": "Calculados a partir dos 9 primeiros dígitos. Um dígito trocado costuma ser erro de digitação."},
                )
            )
        if valid:
            states = CPF_REGIONS[value[8]]
            names = [STATE_NAMES.get(code.strip(), code.strip()) for code in re.split(r",| e ", states)]
            findings.append(
                Finding(
                    "fiscal-region",
                    states,
                    {
                        "digit": value[8],
                        "states": ", ".join(names),
                        "meaning": f"Região fiscal onde o CPF foi emitido, pelo 9º dígito ({value[8]}); não é onde a pessoa mora.",
                    },
                )
            )
        return findings
    if context.query_type == "cnpj":
        valid = cnpj_valid(value)
        findings = [Finding("validity", "válido" if valid else "inválido", {"meaning": "Dígitos verificadores do CNPJ."})]
        if valid:
            order = value[8:12]
            findings.append(Finding("establishment", "matriz" if order == "0001" else f"filial {order}", {"root": value[:8]}))
            findings.append(Finding("formatted", f"{value[:2]}.{value[2:5]}.{value[5:8]}/{value[8:12]}-{value[12:]}", {}))
        return findings
    if context.query_type == "phone":
        phone = parse_phone(value)
        if not phone:
            return [Finding("validity", "formato não reconhecido", {})]
        findings = [Finding("formatted", phone.get("formatted") or phone["e164"], {"e164": phone["e164"]})]
        for label, text in phone.get("formats", []):
            findings.append(Finding("phone-format", text, {"label": label}))
        if phone["country"]:
            findings.append(Finding("country", phone["country"], {"calling_code": f"+{phone['country_code']}"}))
        if phone.get("ddd"):
            findings.append(
                Finding(
                    "phone-region",
                    f"DDD {phone['ddd']} · {phone['region']} ({phone['state']})",
                    {"state": phone["state"], "meaning": "Área onde o número foi emitido; com portabilidade e celulares, não indica onde alguém está."},
                )
            )
            others = phone.get("state_ddds") or []
            findings.append(
                Finding(
                    "state",
                    f"{phone['state_name']} ({phone['state']})",
                    {
                        "capital": phone["capital"],
                        "other_ddds": ", ".join(others),
                        "meaning": ("DDD da capital" if phone["capital"] else "DDD do interior") + (f"; outros DDDs do estado: {', '.join(others)}" if others else "; único DDD do estado"),
                    },
                )
            )
        if phone.get("line_type"):
            meaning = {
                "celular": "Nove dígitos começando por 9, o padrão dos celulares no Brasil desde 2016.",
                "fixo": "Oito dígitos começando de 2 a 5: linha fixa.",
                "não geográfico": phone.get("service_meaning", ""),
            }.get(phone["line_type"], "Oito dígitos começando de 6 a 9: era celular antes de 2016; hoje precisa do 9 na frente.")
            findings.append(Finding("line-type", phone["line_type"], {"meaning": meaning}))
        if phone.get("service"):
            findings.append(Finding("service", f"{phone['service']} · {phone['service_meaning']}", {}))
        if phone.get("suggestion"):
            findings.append(Finding("phone-suggestion", phone["suggestion"], {"meaning": "Como o número fica com o 9 que os celulares ganharam."}))
        return findings
    return []


# --------------------------------------------------------------------------
# CNPJ from public Receita Federal data


def _get_json(url: str, host: str, *, missing: tuple[int, ...] = (404,)) -> tuple[Any, FetchResult]:
    result = FETCH(
        url,
        headers={"Accept": "application/json", "User-Agent": USER_AGENT, "Accept-Language": "pt-BR,pt;q=0.9"},
        allowed_hosts=(host,),
        max_bytes=2 * 1024 * 1024,
        timeout=20.0,
    )
    if result.status in missing:
        return None, result
    if result.status == 429:
        raise NetworkError("the source rate-limited this request (HTTP 429)")
    if result.status >= 400:
        raise NetworkError(f"the source answered HTTP {result.status}")
    try:
        return json.loads(result.body.decode("utf-8")), result
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NetworkError("the source returned invalid JSON") from exc


def _text(value: Any, limit: int = 300) -> str:
    return " ".join(str(value).split())[:limit] if value not in (None, "") else ""


def company_findings(data: dict[str, Any], source: str, digest: str) -> list[Finding]:
    """Receita Federal company record -> findings. Partner names are dropped."""
    findings: list[Finding] = []

    def add(result_type: str, value: Any, extra: dict[str, Any] | None = None) -> None:
        text = _text(value)
        if text:
            findings.append(Finding(result_type, text, extra or {}, source, digest))

    add("organization", data.get("razao_social"), {"role": "razão social"})
    add("trade-name", data.get("nome_fantasia"))
    status = _text(data.get("descricao_situacao_cadastral"))
    if status:
        add("registration-status", status, {"since": _text(data.get("data_situacao_cadastral"), 20), "reason": _text(data.get("descricao_motivo_situacao_cadastral"), 120)})
    add("founded", data.get("data_inicio_atividade"))
    if data.get("cnae_fiscal"):
        add("main-activity", f"{data.get('cnae_fiscal')} · {_text(data.get('cnae_fiscal_descricao'), 200)}")
    for item in (data.get("cnaes_secundarios") or [])[:15]:
        if isinstance(item, dict) and item.get("codigo"):
            add("secondary-activity", f"{item.get('codigo')} · {_text(item.get('descricao'), 200)}")
    add("legal-nature", data.get("natureza_juridica"))
    add("company-size", data.get("porte") or data.get("descricao_porte"))
    capital = data.get("capital_social")
    if capital not in (None, ""):
        try:
            add("share-capital", f"R$ {float(capital):,.2f}".replace(",", "X").replace(".", ",").replace("X", "."))
        except (TypeError, ValueError):
            pass
    add("establishment", data.get("descricao_identificador_matriz_filial") or data.get("descricao_matriz_filial"))
    street = ", ".join(
        part for part in (
            " ".join(part for part in (_text(data.get("descricao_tipo_de_logradouro")), _text(data.get("logradouro"))) if part),
            _text(data.get("numero")), _text(data.get("complemento")), _text(data.get("bairro")),
        ) if part
    )
    city = " - ".join(part for part in (_text(data.get("municipio")), _text(data.get("uf"))) if part)
    address = ", ".join(part for part in (street, city, _text(data.get("cep"))) if part)
    add("address", address, {"city": _text(data.get("municipio")), "state": _text(data.get("uf")), "postal_code": _text(data.get("cep"))})
    phone = _text(data.get("ddd_telefone_1"), 20)
    if phone:
        add("company-phone", phone, {"meaning": "telefone cadastrado da empresa"})
    partners = [item for item in data.get("qsa") or [] if isinstance(item, dict)]
    if partners:
        roles: dict[str, int] = {}
        for partner in partners:
            role = _text(partner.get("qualificacao_socio") or partner.get("descricao_qualificacao_socio"), 80) or "sem qualificação"
            roles[role] = roles.get(role, 0) + 1
        summary = ", ".join(f"{count} {role}" for role, count in sorted(roles.items(), key=lambda item: -item[1]))
        add("partners", f"{len(partners)} sócio(s): {summary}", {"count": len(partners), "roles": roles, "meaning": "Nomes de sócios não são coletados: são dados de pessoas."})
    regime = data.get("opcao_pelo_simples")
    if regime is not None:
        add("tax-regime", "Simples Nacional" if regime else "fora do Simples Nacional")
    return findings


BRASILAPI_CEP = "https://brasilapi.com.br/api/cep/v2/"


def _locate_postal_code(data: dict[str, Any]) -> Finding | None:
    """The company's postal code as a map point (the CEP's centre, not the
    building). BrasilAPI answers without coordinates for many CEPs."""
    postal = re.sub(r"\D", "", str(data.get("cep") or ""))
    if len(postal) != 8:
        return None
    try:
        place, result = _get_json(f"{BRASILAPI_CEP}{postal}", "brasilapi.com.br", missing=(400, 404))
    except NetworkError:
        return None
    coordinates = ((place or {}).get("location") or {}).get("coordinates") or {}
    try:
        latitude, longitude = float(coordinates.get("latitude")), float(coordinates.get("longitude"))
    except (TypeError, ValueError):
        return None
    label = ", ".join(part for part in (_text(place.get("street")), _text(place.get("neighborhood")), _text(place.get("city")), _text(place.get("state"))) if part)
    return Finding(
        "geolocation",
        label or postal,
        {"coordinates": f"{latitude:.6f},{longitude:.6f}", "kind": "place", "precision": "cep", "postal_code": postal,
         "meaning": "centro do CEP do endereço cadastrado, não o prédio"},
        result.final_url,
        result.sha256,
    )


def _cnpj_connector(base: str, host: str, *, locate: bool = False) -> Callable[[ConnectorContext], list[Finding]]:
    def run(context: ConnectorContext) -> list[Finding]:
        if not cnpj_valid(context.query_value):
            return []
        data, result = _get_json(f"{base}{context.query_value}", host, missing=(400, 404))
        if not isinstance(data, dict) or not (data.get("razao_social") or data.get("cnpj")):
            return []
        findings = company_findings(data, result.final_url, result.sha256)
        point = _locate_postal_code(data) if locate else None
        return findings + ([point] if point else [])

    return run


# --------------------------------------------------------------------------
# Places: OpenStreetMap Nominatim


def _place(item: dict[str, Any], source: str, digest: str) -> list[Finding]:
    try:
        latitude, longitude = float(item["lat"]), float(item["lon"])
    except (KeyError, TypeError, ValueError):
        return []
    address = item.get("address") or {}
    name = _text(item.get("display_name"), 300)
    data = {
        "coordinates": f"{latitude:.6f},{longitude:.6f}",
        "precision": "geocoded",
        "kind": "place",
        "category": _text(item.get("category") or item.get("class"), 40),
        "type": _text(item.get("type"), 40),
        "osm": f"{item.get('osm_type', '')}/{item.get('osm_id', '')}",
        "city": _text(address.get("city") or address.get("town") or address.get("village") or address.get("municipality"), 120),
        "state": _text(address.get("state"), 80),
        "country": _text(address.get("country"), 80),
        "postal_code": _text(address.get("postcode"), 20),
    }
    return [
        Finding("geolocation", name, data, source, digest),
        Finding("coordinates", data["coordinates"], {"place": name}, source, digest),
    ]


def _nominatim_connector(context: ConnectorContext) -> list[Finding]:
    value = context.query_value
    coordinates = re.fullmatch(r"(-?\d+(?:\.\d+)?),(-?\d+(?:\.\d+)?)", value)
    if coordinates:
        query = urlencode({"lat": coordinates.group(1), "lon": coordinates.group(2), "format": "jsonv2", "addressdetails": 1, "zoom": 18})
        data, result = _get_json(f"{NOMINATIM}reverse?{query}", "nominatim.openstreetmap.org")
        items = [data] if isinstance(data, dict) and not data.get("error") else []
    else:
        query = urlencode({"q": value, "format": "jsonv2", "addressdetails": 1, "limit": 5})
        data, result = _get_json(f"{NOMINATIM}search?{query}", "nominatim.openstreetmap.org")
        items = data if isinstance(data, list) else []
    findings: list[Finding] = []
    for item in items[:5]:
        if isinstance(item, dict):
            findings.extend(_place(item, result.final_url, result.sha256))
    return findings


for _connector in (
    Connector(
        "br-documents",
        "Documentos e telefones (offline)",
        "Check digits of CPF and CNPJ, head office or branch, CPF fiscal region, phone country, area code and line type. Nothing leaves the machine and no owner is looked up.",
        ("cpf", "cnpj", "phone"),
        _documents_connector,
    ),
    Connector(
        "brasilapi-cnpj",
        "BrasilAPI CNPJ",
        "Public Receita Federal company record via BrasilAPI: names, status, activities, address, size, capital. Partner names are not kept.",
        ("cnpj",),
        _cnpj_connector(BRASILAPI, "brasilapi.com.br", locate=True),
        network=True,
        rate_per_minute=20,
        ttl_seconds=7 * 24 * 3600,
        source_url="https://brasilapi.com.br/docs#tag/CNPJ",
    ),
    Connector(
        "minhareceita-cnpj",
        "Minha Receita",
        "The same public Receita Federal company record from Minha Receita, an independent mirror. Partner names are not kept.",
        ("cnpj",),
        _cnpj_connector(MINHA_RECEITA, "minhareceita.org"),
        network=True,
        rate_per_minute=20,
        ttl_seconds=7 * 24 * 3600,
        source_url="https://docs.minhareceita.org/",
    ),
    Connector(
        "nominatim",
        "OpenStreetMap Nominatim",
        "Geocodes an address or reverse-geocodes coordinates with OpenStreetMap data, within the Nominatim usage policy.",
        ("location",),
        _nominatim_connector,
        network=True,
        rate_per_minute=30,
        ttl_seconds=30 * 24 * 3600,
        source_url="https://operations.osmfoundation.org/policies/nominatim/",
    ),
):
    register_connector(_connector)

