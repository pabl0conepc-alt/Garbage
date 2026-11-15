"""The answer to a multi-source query, read off all its sources at once.

A run stores what each source returned, source by source. The dossier turns
that into what an analyst asks first: who owns it, where it lives, what it
exposes, what it is related to, and what deserves attention. Values seen by
several sources are merged and keep the list of sources that reported them.
Names that do not belong to the queried domain (shared certificates list many
unrelated sites) are left out.

Everything here is computed from stored results; nothing is fetched. Wording
is Brazilian Portuguese, like the rest of the interface.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Iterable

MAX_LIST = 500
SOURCE_NAMES = {
    "abuseipdb": "AbuseIPDB", "brasilapi-cnpj": "BrasilAPI", "br-documents": "verificação offline",
    "certspotter": "Cert Spotter", "circl-hashlookup": "CIRCL", "cisa-kev-local": "CISA KEV",
    "crtsh": "crt.sh", "cymru-asn": "Team Cymru", "dns-doh": "DNS", "first-epss": "EPSS",
    "github": "GitHub", "greynoise": "GreyNoise", "ipinfo": "IPinfo", "local-structure": "análise local",
    "local-workspace": "workspace", "malwarebazaar": "MalwareBazaar", "minhareceita-cnpj": "Minha Receita",
    "nominatim": "OpenStreetMap", "nvd": "NVD", "osv": "OSV", "otx": "AlienVault OTX",
    "peeringdb": "PeeringDB", "rdap": "RDAP", "ripestat": "RIPEstat", "security-txt": "security.txt",
    "shodan": "Shodan", "shodan-internetdb": "Shodan InternetDB", "threatfox": "ThreatFox",
    "tls-certificate": "certificado TLS", "typosquat": "typosquatting", "urlhaus": "URLhaus",
    "urlscan": "urlscan.io", "virustotal": "VirusTotal", "wayback": "Wayback Machine",
    "web-fingerprint": "página web",
}
TYPE_NAMES = {
    "domain": "Domínio", "ipv4": "Endereço IPv4", "ipv6": "Endereço IPv6", "cidr": "Faixa de IP",
    "url": "URL", "email": "E-mail", "md5": "Hash MD5", "sha1": "Hash SHA-1", "sha256": "Hash SHA-256",
    "asn": "Sistema autônomo", "cve": "Vulnerabilidade", "cnpj": "Empresa (CNPJ)", "cpf": "CPF",
    "phone": "Telefone", "location": "Local",
}
SECURITY_HEADERS = ("HSTS", "CSP", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy")


def source_name(connector_id: str) -> str:
    if connector_id.startswith("plugin-"):
        return f"plugin {connector_id[7:]}"
    return SOURCE_NAMES.get(connector_id, connector_id)


class Facts:
    """Results of one run indexed by type, merged by value across sources."""

    def __init__(self, results: Iterable[dict[str, Any]]) -> None:
        self.by_type: dict[str, dict[str, dict[str, Any]]] = {}
        for item in results:
            value = str(item.get("value") or "").strip()
            if not value or item.get("status") not in ("ok", None):
                continue
            bucket = self.by_type.setdefault(item["result_type"], {})
            entry = bucket.setdefault(value.lower(), {"value": value, "data": {}, "sources": []})
            for key, data_value in (item.get("data") or {}).items():
                entry["data"].setdefault(key, data_value)
            if item["connector_id"] not in entry["sources"]:
                entry["sources"].append(item["connector_id"])

    def all(self, *types: str) -> list[dict[str, Any]]:
        merged: dict[str, dict[str, Any]] = {}
        for kind in types:
            for key, entry in self.by_type.get(kind, {}).items():
                target = merged.setdefault(key, {"value": entry["value"], "data": dict(entry["data"]), "sources": []})
                for source in entry["sources"]:
                    if source not in target["sources"]:
                        target["sources"].append(source)
        return list(merged.values())

    def first(self, *types: str) -> dict[str, Any] | None:
        items = self.all(*types)
        return items[0] if items else None

    def value(self, *types: str) -> str:
        entry = self.first(*types)
        return entry["value"] if entry else ""


def _row(label: str, value: Any, *, hint: str = "", sources: Iterable[str] = (), pivot: bool = False) -> dict[str, Any] | None:
    text = str(value).strip() if value not in (None, "") else ""
    if not text:
        return None
    row: dict[str, Any] = {"label": label, "value": text}
    if hint:
        row["hint"] = hint
    names = [source_name(item) for item in sources]
    if names:
        row["sources"] = names
    if pivot:
        row["pivot"] = True
    return row


def _section(section_id: str, title: str, rows: Iterable[dict[str, Any] | None] = (), *, items: list[dict[str, Any]] | None = None, total: int | None = None, pivot: bool = False, note: str = "") -> dict[str, Any] | None:
    kept = [row for row in rows if row]
    listed = items or []
    if not kept and not listed:
        return None
    section: dict[str, Any] = {"id": section_id, "title": title, "rows": kept}
    if listed:
        section["list"] = {"items": listed[:MAX_LIST], "total": total if total is not None else len(listed), "pivot": pivot}
    if note:
        section["note"] = note
    return section


def _date(value: Any) -> str:
    text = str(value or "")
    match = re.match(r"(\d{4})-?(\d{2})-?(\d{2})", text)
    return f"{match.group(3)}/{match.group(2)}/{match.group(1)}" if match else text


def _years_since(value: Any) -> int | None:
    match = re.match(r"(\d{4})-?(\d{2})-?(\d{2})", str(value or ""))
    if not match:
        return None
    try:
        then = datetime(int(match.group(1)), int(match.group(2)), int(match.group(3)), tzinfo=timezone.utc)
    except ValueError:
        return None
    return int((datetime.now(timezone.utc) - then).days // 365.25)


def _belongs(name: str, domain: str) -> bool:
    name = name.lower().lstrip("*.").rstrip(".")
    return name == domain or name.endswith(f".{domain}")


# ---------------------------------------------------------------------------
# Domain


def _domain(value: str, facts: Facts) -> dict[str, Any]:
    domain = value.lower()
    events = {entry["data"].get("action", ""): entry["value"] for entry in facts.all("rdap-event")}
    created = events.get("registration") or events.get("registered") or ""
    nameservers = sorted({entry["value"].lower().rstrip(".") for entry in facts.all("nameserver", "dns-ns")})
    addresses = facts.all("dns-a", "dns-aaaa")
    http = facts.first("http-response")
    title = facts.value("page-title")
    trust = facts.first("tls-trust")
    validity = facts.first("cert-validity")
    issuer = facts.first("cert-issuer")
    hosting = ""
    for scan in facts.all("scan"):
        data = scan["data"]
        if str(data.get("page_domain", "")).lower() in (domain, f"www.{domain}") and data.get("asn_name"):
            hosting = f"{data['asn_name']} ({data.get('asn', '')})".replace(" ()", "")
            break

    # Subdomains: every source, only names under the domain, wildcards folded.
    subdomains: dict[str, dict[str, Any]] = {}
    for entry in facts.all("subdomain", "ct-name", "cert-san", "hostname"):
        name = entry["value"].lower().lstrip("*.").rstrip(".")
        if not _belongs(name, domain) or name == domain:
            continue
        item = subdomains.setdefault(name, {"value": name, "sources": set(), "first_seen": "", "last_seen": ""})
        item["sources"].update(entry["sources"])
        for key in ("first_seen", "last_seen"):
            seen = str(entry["data"].get(key) or "")
            if seen and (not item[key] or (seen < item[key] if key == "first_seen" else seen > item[key])):
                item[key] = seen
    sub_items = [
        {
            "value": item["value"],
            "meta": " · ".join(part for part in (
                f"visto até {_date(item['last_seen'])}" if item["last_seen"] else "",
                ", ".join(source_name(source) for source in sorted(item["sources"])),
            ) if part),
        }
        for item in sorted(subdomains.values(), key=lambda entry: (entry["value"].count("."), entry["value"]))
    ]

    spf = next((entry["value"] for entry in facts.all("dns-txt") if entry["data"].get("policy") == "spf" or entry["value"].lower().startswith("v=spf1")), "")
    dmarc = facts.value("dns-dmarc")
    dmarc_policy = (re.search(r"\bp=(\w+)", dmarc or "") or [None, ""])[1]
    mx = sorted({re.sub(r"^\d+\s+", "", entry["value"]).rstrip(".") for entry in facts.all("dns-mx")})
    mail_provider = ""
    joined_mx = " ".join(mx).lower()
    for marker, provider in (("outlook.com", "Microsoft 365"), ("google.com", "Google Workspace"), ("googlemail.com", "Google Workspace"), ("zoho", "Zoho"), ("protonmail", "Proton Mail"), ("mimecast", "Mimecast"), ("pphosted", "Proofpoint")):
        if marker in joined_mx:
            mail_provider = provider
            break

    present = {entry["value"] for entry in facts.all("security-header")}
    missing = [name for name in SECURITY_HEADERS if name not in present and any(entry["value"] == name for entry in facts.all("missing-header"))]
    technologies = sorted({entry["value"] for entry in facts.all("technology")})
    lookalikes = facts.all("typosquat")
    pulses = facts.first("pulse-count")
    wayback = facts.first("archive-summary")
    days_left = validity["data"].get("days_remaining") if validity else None

    flags: list[dict[str, str]] = []
    if isinstance(days_left, int) and days_left < 15:
        flags.append({"level": "high" if days_left < 0 else "medium", "text": f"Certificado TLS {'vencido' if days_left < 0 else f'vence em {days_left} dia(s)'}."})
    if trust and trust["value"] != "trusted":
        flags.append({"level": "high", "text": "O certificado TLS não é confiável para este nome."})
    if mx and not dmarc:
        flags.append({"level": "medium", "text": "Recebe e-mail mas não publica DMARC: fica mais fácil falsificar o remetente."})
    elif dmarc_policy == "none":
        flags.append({"level": "info", "text": "DMARC em modo só de observação (p=none)."})
    if mx and not spf:
        flags.append({"level": "medium", "text": "Recebe e-mail mas não publica SPF."})
    if lookalikes:
        flags.append({"level": "medium", "text": f"{len(lookalikes)} domínio(s) parecido(s) registrado(s)."})
    if pulses and str(pulses["value"]) not in ("0", ""):
        flags.append({"level": "high", "text": f"Citado em {pulses['value']} relatório(s) de ameaça na AlienVault OTX."})
    if len(missing) >= 3:
        flags.append({"level": "info", "text": f"Faltam {len(missing)} cabeçalhos de segurança no site."})
    age = _years_since(created)
    if age is not None and age < 1:
        flags.append({"level": "medium", "text": "Domínio registrado há menos de um ano."})

    first_capture = _date((wayback or {}).get("data", {}).get("first", "")) if wayback else ""
    sections = [
        _section("registration", "Registro", [
            _row("Situação", facts.value("rdap-status"), sources=["rdap"]),
            _row("Criado em", _date(created), hint=f"há {age} ano(s)" if age else "", sources=["rdap"]),
            _row("Expira em", _date(events.get("expiration", "")), sources=["rdap"]),
            _row("Última alteração", _date(events.get("last changed", "")), sources=["rdap"]),
            _row("DNSSEC", "assinado" if facts.value("dnssec") == "signed" else facts.value("dnssec"), sources=["rdap"]),
            _row("Servidores de nome", ", ".join(nameservers), sources=["rdap", "dns-doh"]),
        ]),
        _section("hosting", "Onde está hospedado", [
            _row("Hospedagem", hosting, sources=["urlscan"]),
            _row("Servidor que respondeu", (http or {}).get("data", {}).get("address", ""), sources=["web-fingerprint"], pivot=True),
        ], items=[{"value": entry["value"], "meta": "IPv6" if ":" in entry["value"] else "IPv4"} for entry in addresses], pivot=True),
        _section("mail", "E-mail", [
            _row("Provedor", mail_provider),
            _row("Servidores MX", ", ".join(mx), sources=["dns-doh"]),
            _row("SPF", spf or ("não publicado" if mx else ""), sources=["dns-doh"]),
            _row("DMARC", dmarc or ("não publicado" if mx else ""), hint=f"política {dmarc_policy}" if dmarc_policy else "", sources=["dns-doh"]),
        ]),
        _section("web", "Site", [
            _row("Título", title, sources=["web-fingerprint"]),
            _row("Endereço final", (http or {}).get("data", {}).get("final_url", ""), sources=["web-fingerprint"]),
            _row("Resposta HTTP", (http or {}).get("value", "")),
            _row("Tecnologias", ", ".join(technologies), sources=["web-fingerprint"]),
            _row("Cabeçalhos de segurança", f"{len(present)} presentes" + (f"; faltam {', '.join(missing)}" if missing else ""), sources=["web-fingerprint"]) if present or missing else None,
            _row("Servidor anunciado", ", ".join(entry["value"] for entry in facts.all("disclosure-header"))),
            _row("Hash do favicon", facts.value("favicon"), hint="mmh3, igual ao do Shodan"),
        ]),
        _section("tls", "Certificado TLS", [
            _row("Emitido para", facts.value("cert-subject")),
            _row("Emissor", (issuer or {}).get("data", {}).get("organization") or (issuer or {}).get("value", "")),
            _row("Validade", (validity or {}).get("value", "").replace("T", " ").replace("Z", ""), hint=f"{days_left} dia(s) restantes" if isinstance(days_left, int) else ""),
            _row("Confiança", {"trusted": "confiável"}.get((trust or {}).get("value", ""), (trust or {}).get("value", ""))),
            _row("Chave", facts.value("cert-key")),
        ]),
        _section("subdomains", "Subdomínios", items=sub_items, total=len(sub_items), pivot=True,
                 note="Nomes que aparecem em certificados públicos e registros DNS. Existir num certificado não garante que esteja no ar."),
        _section("history", "Histórico", [
            _row("Primeira captura no Wayback", first_capture, sources=["wayback"]),
            _row("Capturas", (wayback or {}).get("value", "").replace("distinct captures", "capturas distintas"), sources=["wayback"]),
            _row("Varreduras públicas (urlscan)", str(len(facts.all("scan"))) if facts.all("scan") else "", sources=["urlscan"]),
        ]),
        _section("reputation", "Reputação", [
            _row("AlienVault OTX", f"{pulses['value']} relatório(s) de ameaça" if pulses else "", sources=["otx"]),
            _row("URLhaus", f"{len(facts.all('malicious-url'))} URL(s) de malware" if facts.all("malicious-url") else ""),
            _row("ThreatFox", f"{len(facts.all('ioc'))} indicador(es)" if facts.all("ioc") else ""),
        ]),
        _section("lookalikes", "Domínios parecidos registrados", items=[
            {"value": entry["value"], "meta": str(entry["data"].get("kind", ""))} for entry in lookalikes
        ], pivot=True, note="Existem e respondem no DNS; isso não quer dizer que sejam maliciosos."),
    ]
    facts_line = [
        {"label": "Criado", "value": _date(created)} if created else None,
        {"label": "IPs", "value": str(len(addresses))} if addresses else None,
        {"label": "Subdomínios", "value": str(len(sub_items))} if sub_items else None,
        {"label": "E-mail", "value": mail_provider or ("sim" if mx else "")} if mx else None,
        {"label": "Hospedagem", "value": hosting.split(" (")[0]} if hosting else None,
    ]
    return {
        "title": domain,
        "subtitle": " · ".join(part for part in (title, f"registrado em {_date(created)}" if created else "") if part),
        "facts": [item for item in facts_line if item],
        "flags": flags,
        "sections": [section for section in sections if section],
    }


# ---------------------------------------------------------------------------
# IP address


def _ip(value: str, facts: Facts) -> dict[str, Any]:
    owner = facts.value("network-owner") or facts.value("as-name") or facts.value("isp")
    asn_entry = facts.first("origin-asn", "asn")
    asn = asn_entry["value"] if asn_entry else ""
    prefix = (asn_entry or {}).get("data", {}).get("prefix", "") or facts.value("cidr")
    geo = facts.first("geolocation")
    host = facts.first("host")
    # The reverse name (IPinfo) first; names other scanners saw come after.
    named = facts.all("hostname")
    hostnames = sorted({entry["value"].lower() for entry in named}, key=lambda name: (not any(
        entry["value"].lower() == name and "ipinfo" in entry["sources"] for entry in named), name))
    ports: dict[str, dict[str, Any]] = {}
    for entry in facts.all("open-port"):
        ports.setdefault(entry["value"], {"value": entry["value"], "meta": ""})
    for entry in facts.all("service"):
        port = entry["value"].split("/")[0]
        detail = " ".join(part for part in (str(entry["data"].get("product") or ""), str(entry["data"].get("module") or "")) if part)
        ports.setdefault(port, {"value": port, "meta": ""})
        if detail:
            ports[port]["meta"] = detail
    seen_domains: dict[str, int] = {}
    for entry in facts.all("scan"):
        name = str(entry["data"].get("page_domain") or "").lower()
        if name:
            seen_domains[name] = seen_domains.get(name, 0) + 1
    noise = facts.first("internet-noise")
    abuse = facts.first("abuse-score")
    pulses = facts.first("pulse-count")
    vulns = facts.all("vulnerability", "cve")

    flags: list[dict[str, str]] = []
    if noise and noise["value"] not in ("not observed", "benign"):
        flags.append({"level": "high", "text": f"GreyNoise: {noise['value']}."})
    if abuse and str(abuse["value"]).isdigit() and int(abuse["value"]) >= 25:
        flags.append({"level": "high", "text": f"Pontuação de abuso {abuse['value']}% na AbuseIPDB."})
    if pulses and str(pulses["value"]) not in ("0", ""):
        flags.append({"level": "high", "text": f"Citado em {pulses['value']} relatório(s) de ameaça na AlienVault OTX."})
    if vulns:
        flags.append({"level": "medium", "text": f"{len(vulns)} vulnerabilidade(s) inferida(s) pelo Shodan para os serviços expostos."})
    if (host or {}).get("data", {}).get("ports") and len(ports) > 10:
        flags.append({"level": "info", "text": f"{len(ports)} portas abertas."})

    place = (geo or {}).get("value", "")
    coordinates = (geo or {}).get("data", {}).get("coordinates", "")
    sections = [
        _section("network", "Rede", [
            _row("Dono", owner, sources=["ipinfo", "cymru-asn"]),
            _row("Sistema autônomo", asn, hint=(asn_entry or {}).get("data", {}).get("holder", ""), pivot=True),
            _row("Bloco anunciado", prefix, pivot=True),
            _row("Faixa registrada", facts.value("ip-range"), sources=["rdap"]),
            _row("Nome no registro", facts.value("rdap-name"), sources=["rdap"]),
            _row("Contato de abuso", facts.value("abuse-contact"), sources=["rdap", "ripestat"]),
            _row("Anycast", "sim" if (facts.first("network-owner") or {}).get("data", {}).get("anycast") else ""),
        ]),
        _section("location", "Localização aproximada da rede", [
            _row("Local", place, hint="da rede, não de uma pessoa", sources=["ipinfo"]),
            _row("Fuso horário", (geo or {}).get("data", {}).get("timezone", "")),
        ]),
        _section("names", "Nomes neste IP", items=[{"value": name, "meta": ""} for name in hostnames], pivot=True),
        _section("services", "Serviços expostos", [
            _row("Tags", ", ".join(sorted({entry["value"] for entry in facts.all("tag")}))),
            _row("Sistema", (host or {}).get("data", {}).get("os", "")),
        ], items=sorted(ports.values(), key=lambda item: int(item["value"]) if item["value"].isdigit() else 0), note="Dados de varreduras do Shodan; podem estar desatualizados."),
        _section("web", "Site neste IP", [
            _row("Título", facts.value("page-title")),
            _row("Certificado para", facts.value("cert-subject")),
            _row("Emissor", (facts.first("cert-issuer") or {}).get("data", {}).get("organization", "")),
        ]),
        _section("seen-domains", "Domínios vistos em varreduras públicas", items=[
            {"value": name, "meta": f"{count} varredura(s)"} for name, count in sorted(seen_domains.items(), key=lambda item: -item[1])
        ], pivot=True, note="Sites que o urlscan.io viu servidos por este IP."),
        _section("reputation", "Reputação", [
            _row("GreyNoise", {"not observed": "não visto fazendo varreduras em massa"}.get((noise or {}).get("value", ""), (noise or {}).get("value", ""))),
            _row("AbuseIPDB", f"{abuse['value']}%" if abuse else ""),
            _row("AlienVault OTX", f"{pulses['value']} relatório(s)" if pulses else ""),
        ]),
    ]
    facts_line = [
        {"label": "Dono", "value": owner} if owner else None,
        {"label": "ASN", "value": asn} if asn else None,
        {"label": "Local", "value": place} if place else None,
        {"label": "Portas", "value": str(len(ports))} if ports else None,
    ]
    result: dict[str, Any] = {
        "title": value,
        "subtitle": " · ".join(part for part in (hostnames[0] if hostnames else "", owner) if part),
        "facts": [item for item in facts_line if item],
        "flags": flags,
        "sections": [section for section in sections if section],
    }
    point = _point(coordinates, place)
    if point:
        result["map"] = {**point, "precision": "rede (aproximada)"}
    return result


def _point(coordinates: str, label: str) -> dict[str, Any] | None:
    match = re.match(r"\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)", coordinates or "")
    if not match:
        return None
    return {"lat": float(match.group(1)), "lon": float(match.group(2)), "label": label}


# ---------------------------------------------------------------------------
# Company, place, documents


def _cnpj(value: str, facts: Facts) -> dict[str, Any]:
    name = facts.value("organization")
    status = facts.first("registration-status")
    founded = facts.value("founded")
    partners = facts.first("partners")
    flags = []
    if status and status["value"].upper() != "ATIVA":
        flags.append({"level": "high", "text": f"Situação cadastral: {status['value']}."})
    if facts.value("validity") == "inválido":
        flags.append({"level": "high", "text": "Dígitos verificadores inválidos."})
    sources = ["brasilapi-cnpj", "minhareceita-cnpj"]
    sections = [
        _section("company", "Empresa", [
            _row("Razão social", name, sources=sources),
            _row("Nome fantasia", facts.value("trade-name")),
            _row("CNPJ", facts.value("formatted")),
            _row("Situação", (status or {}).get("value", ""), hint=f"desde {_date(status['data'].get('since'))}" if status and status["data"].get("since") else ""),
            _row("Início das atividades", _date(founded), hint=f"há {_years_since(founded)} ano(s)" if _years_since(founded) else ""),
            _row("Estabelecimento", facts.value("establishment")),
            _row("Natureza jurídica", facts.value("legal-nature")),
            _row("Porte", facts.value("company-size")),
            _row("Capital social", facts.value("share-capital")),
            _row("Regime", facts.value("tax-regime")),
        ]),
        _section("activity", "Atividades", [_row("Principal", facts.value("main-activity"))],
                 items=[{"value": entry["value"], "meta": "secundária"} for entry in facts.all("secondary-activity")]),
        _section("contact", "Endereço e contato", [
            _row("Endereço", facts.value("address"), pivot=True),
            _row("Telefone da empresa", facts.value("company-phone")),
        ]),
        _section("partners", "Quadro societário", [
            _row("Sócios", (partners or {}).get("value", ""), hint="nomes de sócios não são coletados: são dados de pessoas"),
        ]),
    ]
    facts_line = [
        {"label": "Situação", "value": status["value"]} if status else None,
        {"label": "Desde", "value": _date(founded)} if founded else None,
        {"label": "Porte", "value": facts.value("company-size")} if facts.value("company-size") else None,
        {"label": "UF", "value": (facts.first("address") or {}).get("data", {}).get("state", "")} if facts.first("address") else None,
    ]
    return {
        "title": name or value,
        "subtitle": " · ".join(part for part in (facts.value("trade-name"), facts.value("formatted") or value) if part),
        "facts": [item for item in facts_line if item and item["value"]],
        "flags": flags,
        "sections": [section for section in sections if section],
    }


def _location(value: str, facts: Facts) -> dict[str, Any]:
    places = facts.all("geolocation")
    best = places[0] if places else None
    data = (best or {}).get("data", {})
    sections = [
        _section("place", "Local encontrado", [
            _row("Endereço", (best or {}).get("value", "")),
            _row("Coordenadas", data.get("coordinates", ""), pivot=True),
            _row("Cidade", data.get("city", "")),
            _row("Estado", data.get("state", "")),
            _row("País", data.get("country", "")),
            _row("CEP", data.get("postal_code", "")),
            _row("Tipo", " · ".join(part for part in (data.get("category", ""), data.get("type", "")) if part)),
        ]),
        _section("others", "Outros resultados", items=[
            {"value": entry["value"], "meta": entry["data"].get("coordinates", "")} for entry in places[1:]
        ]),
    ]
    result: dict[str, Any] = {
        "title": _place_title((best or {}).get("value", "")) or value,
        "subtitle": (best or {}).get("value", ""),
        "facts": [item for item in (
            {"label": "Cidade", "value": data.get("city", "")},
            {"label": "Estado", "value": data.get("state", "")},
            {"label": "País", "value": data.get("country", "")},
        ) if item["value"]],
        "flags": [] if best else [{"level": "info", "text": "O OpenStreetMap não encontrou esse endereço. Tente com cidade e estado."}],
        "sections": [section for section in sections if section],
    }
    point = _point(data.get("coordinates", ""), (best or {}).get("value", ""))
    if point:
        result["map"] = {**point, "precision": "geocodificado"}
    return result


def _place_title(display_name: str) -> str:
    """"1000, Avenida Paulista, Bela Vista, ..." -> "Avenida Paulista, 1000"."""
    parts = [part.strip() for part in display_name.split(",") if part.strip()]
    if not parts:
        return ""
    if parts[0].replace("-", "").isdigit() and len(parts) > 1:
        return f"{parts[1]}, {parts[0]}"
    return parts[0]


def _documents(query_type: str, value: str, facts: Facts) -> dict[str, Any]:
    rows = [
        _row("Formato", facts.value("formatted")),
        _row("Validade", facts.value("validity")),
        _row("Região fiscal", facts.value("fiscal-region"), hint="onde foi emitido, não onde a pessoa mora"),
        _row("País", facts.value("country")),
        _row("DDD", facts.value("phone-region"), hint="área de emissão; não indica onde alguém está"),
        _row("Tipo de linha", facts.value("line-type")),
    ]
    return {
        "title": facts.value("formatted") or value,
        "subtitle": "Só verificação offline: o GARBAGE não busca o dono de CPF ou telefone.",
        "facts": [],
        "flags": [{"level": "high", "text": "Número inválido."}] if facts.value("validity") == "inválido" else [],
        "sections": [section for section in [_section("facts", "Verificação", rows)] if section],
    }


def _generic(facts: Facts, labels: dict[str, str]) -> dict[str, Any]:
    sections = []
    for result_type, entries in sorted(facts.by_type.items(), key=lambda item: -len(item[1])):
        if result_type in ("fact", "warning"):
            continue
        items = [{"value": entry["value"], "meta": ", ".join(source_name(source) for source in entry["sources"])} for entry in entries.values()]
        section = _section(result_type, labels.get(result_type, result_type), items=items)
        if section:
            sections.append(section)
    return {"facts": [], "flags": [], "sections": sections[:12]}


# ---------------------------------------------------------------------------


def build(run: dict[str, Any], labels: dict[str, str] | None = None) -> dict[str, Any]:
    """Dossier for one stored run (as returned by intel.get_run)."""
    query_type, value = run.get("query_type", ""), run.get("query_value", "")
    facts = Facts(run.get("results") or [])
    if query_type == "domain":
        body = _domain(value, facts)
    elif query_type in ("ipv4", "ipv6"):
        body = _ip(value, facts)
    elif query_type == "cnpj":
        body = _cnpj(value, facts)
    elif query_type == "location":
        body = _location(value, facts)
    elif query_type in ("cpf", "phone"):
        body = _documents(query_type, value, facts)
    else:
        body = {"title": value, "subtitle": "", **_generic(facts, labels or {})}
    body.setdefault("title", value)
    body.setdefault("subtitle", "")
    sources = run.get("sources") or []
    coverage = {
        "answered": sum(1 for item in sources if item["status"] == "ok"),
        "empty": sum(1 for item in sources if item["status"] == "empty"),
        "failed": [source_name(item["connector_id"]) for item in sources if item["status"] in ("error", "rate-limited")],
        "missing_key": [source_name(item["connector_id"]) for item in sources if item["status"] == "key-missing"],
        "network_off": sum(1 for item in sources if item["status"] in ("network-disabled", "target-contact-disabled")),
        "pending": sum(1 for item in sources if item["status"] == "pending"),
    }
    return {"type": query_type, "type_label": TYPE_NAMES.get(query_type, query_type), "value": value, **body, "coverage": coverage}
