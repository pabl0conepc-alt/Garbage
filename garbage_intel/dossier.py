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
    "misp": "MISP", "opencti": "OpenCTI", "ransomware-live": "ransomware.live", "phishing-lists": "listas de phishing",
    "reverse-ip": "HackerTarget", "mnemonic-pdns": "Mnemonic", "ip-lists": "listas públicas", "dnsbl": "DNSBL",
    "hackertarget-hosts": "HackerTarget", "otx-hosts": "OTX", "subdomain-center": "subdomain.center", "dns-common-names": "nomes comuns",
    "registrobr-cnpj": "Registro.br", "sancoes-cgu": "CGU (Portal da Transparência)", "contratos-cgu": "CGU (Portal da Transparência)",
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
RDAP_STATUS = {
    "active": "ativo", "inactive": "inativo", "client delete prohibited": "exclusão bloqueada",
    "client transfer prohibited": "transferência bloqueada", "client update prohibited": "alteração bloqueada",
    "server delete prohibited": "exclusão bloqueada pelo registro", "server transfer prohibited": "transferência bloqueada pelo registro",
    "server update prohibited": "alteração bloqueada pelo registro", "client hold": "suspenso", "server hold": "suspenso pelo registro",
    "pending delete": "exclusão pendente", "redemption period": "em recuperação", "auto renew period": "renovado",
}
LOOKALIKE_KINDS = {
    "replacement": "letra trocada", "omission": "letra a menos", "insertion": "letra a mais", "transposition": "letras invertidas",
    "repetition": "letra repetida", "homoglyph": "caractere parecido", "bitsquatting": "bit trocado", "tld-swap": "outro TLD",
    "hyphenation": "com hífen", "subdomain": "subdomínio", "vowel-swap": "vogal trocada", "addition": "letra a mais",
}


def _status_text(facts: "Facts") -> str:
    return ", ".join(RDAP_STATUS.get(entry["value"].lower(), entry["value"]) for entry in facts.all("rdap-status"))


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
        item = subdomains.setdefault(name, {"value": name, "sources": set(), "first_seen": "", "last_seen": "", "ip": ""})
        item["sources"].update(entry["sources"])
        item["ip"] = item["ip"] or str(entry["data"].get("ip") or "")
        for key in ("first_seen", "last_seen"):
            seen = str(entry["data"].get(key) or "")
            if seen and (not item[key] or (seen < item[key] if key == "first_seen" else seen > item[key])):
                item[key] = seen
    sub_items = [
        {
            "value": item["value"],
            "meta": " · ".join(part for part in (
                item["ip"],
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
            _row("Situação", _status_text(facts), sources=["rdap"]),
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
                 note="Nomes vistos em certificados públicos, registros DNS e bases passivas (HackerTarget, OTX, subdomain.center). O IP mostrado é o que a fonte viu; nem todo nome está no ar hoje."),
        _section("urls", "URLs vistas", items=[
            {"value": entry["value"], "meta": _date(entry["data"].get("date", ""))} for entry in facts.all("observed-url")
        ], pivot=True),
        _section("dns-history", "Histórico de DNS", items=[
            {"value": entry["value"], "meta": " · ".join(part for part in (str(entry["data"].get("rrtype") or ""), f"{_date(entry['data'].get('first_seen'))} → {_date(entry['data'].get('last_seen'))}") if part)}
            for entry in sorted(facts.all("pdns-answer"), key=lambda entry: str(entry["data"].get("last_seen") or ""), reverse=True)
        ], pivot=True, note="Para onde o domínio já apontou: endereços e nomes, com a primeira e a última vez vistos." if facts.all("pdns-answer") else ""),
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
            {"value": entry["value"], "meta": LOOKALIKE_KINDS.get(str(entry["data"].get("kind", "")), str(entry["data"].get("kind", "")))} for entry in lookalikes
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
    c2 = facts.first("botnet-c2")
    drop = facts.first("drop-listed")
    tor = facts.first("tor-exit")
    cloud = facts.first("cloud-range")
    blocklists = facts.all("blocklist")
    blockcheck = facts.first("blocklist-check")
    if c2:
        flags.append({"level": "high", "text": f"Feodo Tracker: {c2['value']}" + (f", {c2['data'].get('status')}" if c2["data"].get("status") else "") + "."})
    if drop:
        flags.append({"level": "high", "text": f"Na Spamhaus DROP: {drop['value']}."})
    if blocklists:
        flags.append({"level": "medium", "text": f"Em {len(blocklists)} lista(s) antispam: {', '.join(entry['value'] for entry in blocklists)}."})
    if tor:
        flags.append({"level": "info", "text": "Nó de saída da rede Tor."})
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
            _row(
                "Nuvem ou CDN",
                " · ".join(part for part in (cloud["value"], str(cloud["data"].get("service") or ""), str(cloud["data"].get("region") or "")) if part) if cloud else "",
                hint=f"faixa publicada {cloud['data'].get('prefix', '')}" if cloud else "",
                sources=["ip-lists"] if cloud else (),
            ),
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
            _row("Botnet (Feodo Tracker)", c2["value"] if c2 else ("não listado" if facts.first("lists-checked") else ""), sources=["ip-lists"]),
            _row("Spamhaus DROP", drop["value"] if drop else ("não listado" if facts.first("lists-checked") else "")),
            _row("Rede Tor", "nó de saída" if tor else ("não é saída Tor" if facts.first("lists-checked") else "")),
            _row(
                "Listas antispam",
                (", ".join(entry["value"] for entry in blocklists) or "nenhuma") if blockcheck else "",
                hint=" · ".join(part for part in (
                    f"limpo em {len(blockcheck['data'].get('clean') or [])}" if blockcheck else "",
                    f"sem resposta: {', '.join(blockcheck['data'].get('unanswered') or [])}" if blockcheck and blockcheck["data"].get("unanswered") else "",
                ) if part),
                sources=["dnsbl"] if blockcheck else (),
            ),
        ]),
        _section("cohosted", "Domínios no mesmo IP", items=[
            {"value": entry["value"], "meta": ""} for entry in facts.all("cohosted-domain")
        ], pivot=True, note="Em IPs de CDN ou hospedagem compartilhada, milhares de sites sem relação dividem o mesmo endereço." if facts.all("cohosted-domain") else ""),
        _section("pdns", "Histórico de DNS", items=[
            {"value": entry["value"], "meta": f"{_date(entry['data'].get('first_seen'))} → {_date(entry['data'].get('last_seen'))}"}
            for entry in sorted(facts.all("pdns-name"), key=lambda entry: str(entry["data"].get("last_seen") or ""), reverse=True)
        ], pivot=True, note="Nomes que já apontaram para este IP, com a primeira e a última vez que foram vistos." if facts.all("pdns-name") else ""),
    ]
    facts_line = [
        {"label": "Dono", "value": re.sub(r"^AS\d+\s+", "", owner)} if owner else None,
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


def brl(value: float) -> str:
    return f"R$ {value:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")


def _iso(value: Any) -> str:
    """dd/mm/yyyy or yyyy-mm-dd as yyyy-mm-dd, for comparisons; '' otherwise."""
    text = str(value or "")
    match = re.match(r"(\d{2})/(\d{2})/(\d{4})", text)
    if match:
        return f"{match.group(3)}-{match.group(2)}-{match.group(1)}"
    match = re.match(r"(\d{4})-(\d{2})-(\d{2})", text)
    return match.group(0) if match else ""


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
    sanctions = facts.all("sanction")
    if sanctions:
        lists = sorted({entry["data"].get("list", "").split(" (")[0] for entry in sanctions if entry["data"].get("list")})
        flags.append({"level": "high", "text": f"{len(sanctions)} registro(s) em listas federais de sanção: {', '.join(lists)}."})
    if _years_since(founded) == 0:
        flags.append({"level": "medium", "text": f"Empresa aberta há menos de um ano ({_date(founded)})."})
    if "individual" in facts.value("legal-nature").lower():
        flags.append({"level": "info", "text": "Empresário individual: o nome da empresa é o do titular; o CPF que vem no nome fica mascarado."})
    holder = facts.first("registrobr-holder")
    domains = facts.all("company-domain")
    contracts = sorted(facts.all("contract"), key=lambda entry: -(entry["data"].get("amount") or 0))
    contract_summary = facts.first("contracts-summary")
    payments = sorted(facts.all("payment"), key=lambda entry: -(entry["data"].get("amount") or 0))
    payment_years = sorted(facts.all("payments-summary"), key=lambda entry: -int(entry["data"].get("year") or 0))
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    active = [entry for entry in contracts if _iso(entry["data"].get("end")) >= today]
    if sanctions and active:
        flags.append({"level": "high", "text": f"Empresa com sanção federal e {len(active)} contrato(s) federal(is) ainda vigente(s)."})
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
        _section(
            "internet",
            "Na internet",
            [
                _row(
                    "No Registro.br",
                    " · ".join(part for part in (
                        f"{holder['data'].get('domains') or 0} domínio(s) .br",
                        f"{holder['data'].get('ip_blocks')} bloco(s) de IP" if holder["data"].get("ip_blocks") else "",
                        f"{holder['data'].get('asns')} AS" if holder["data"].get("asns") else "",
                    ) if part) if holder else "",
                    hint=(f"titular desde {_date(holder['data'].get('since'))}" if holder["data"].get("since") else "") + (" · contado na matriz" if holder["data"].get("holder") == "matriz" else "") if holder else "",
                    sources=["registrobr-cnpj"] if holder else (),
                ),
            ],
            items=[
                {"value": entry["value"], "meta": entry["data"].get("how", "")}
                for entry in sorted(domains, key=lambda entry: not entry["data"].get("confirmed"))
            ],
            pivot=True,
            note="O Registro.br não lista os domínios de um titular; os sites acima são os prováveis, confirmados pelo CNPJ do titular." if holder and domains else "",
        ),
        _section(
            "contracts",
            "Contratos com o governo federal",
            [
                _row(
                    "Contratos",
                    f"{contract_summary['value']} · {brl(contract_summary['data'].get('total') or 0)}" if contract_summary and contract_summary["data"].get("count") else ("nenhum encontrado" if contract_summary else ""),
                    hint="soma do valor final de cada contrato listado" + (" (lista cortada nos primeiros)" if contract_summary and contract_summary["data"].get("more") else "") if contract_summary and contract_summary["data"].get("count") else "",
                    sources=["contratos-cgu"] if contract_summary else (),
                ),
                _row("Vigentes", f"{len(active)}" if contracts else ""),
                _row(
                    "Órgãos principais",
                    "; ".join(f"{name} ({count})" for name, count in list((contract_summary or {}).get("data", {}).get("organs", {}).items())[:4]),
                ),
            ],
            items=[
                {
                    "value": f"{brl(entry['data']['amount'])} · {entry['value']}" if entry["data"].get("amount") else entry["value"],
                    "meta": " · ".join(part for part in (
                        entry["data"].get("organ", ""),
                        f"assinado em {entry['data']['signed']}" if entry["data"].get("signed") else "",
                        f"vigência até {entry['data']['end']}" if entry["data"].get("end") else "",
                        entry["data"].get("modality", ""),
                    ) if part),
                }
                for entry in contracts
            ],
        ),
        _section(
            "payments",
            "Pagamentos federais",
            [
                _row(
                    str(entry["data"].get("year")),
                    f"{brl(entry['data'].get('listed_total') or 0)} em {entry['data'].get('count')} pagamento(s)" if entry["data"].get("count") else "nenhum pagamento",
                    hint="só os maiores do ano; o total pode ser maior" if entry["data"].get("top_only") else "",
                    sources=["contratos-cgu"],
                )
                for entry in payment_years
            ],
            items=[
                {
                    "value": entry["value"],
                    "meta": " · ".join(part for part in (entry["data"].get("date", ""), entry["data"].get("program", ""), entry["data"].get("document", "")) if part),
                }
                for entry in payments
            ],
        ),
        _section(
            "sanctions",
            "Sanções federais",
            [_row("Resultado", facts.value("sanction-check"), hint=f"listas: {facts.first('sanction-check')['data'].get('lists', '')}" if facts.first("sanction-check") else "", sources=["sancoes-cgu"])],
            items=[
                {
                    "value": entry["value"],
                    "meta": " · ".join(part for part in (
                        entry["data"].get("list", "").split(" (")[0],
                        f"de {entry['data']['start']}" if entry["data"].get("start") else "",
                        f"até {entry['data']['end']}" if entry["data"].get("end") else "",
                        f"processo {entry['data']['process']}" if entry["data"].get("process") else "",
                    ) if part),
                }
                for entry in sanctions
            ],
        ),
    ]
    facts_line = [
        {"label": "Situação", "value": status["value"]} if status else None,
        {"label": "Desde", "value": _date(founded)} if founded else None,
        {"label": "Porte", "value": facts.value("company-size")} if facts.value("company-size") else None,
        {"label": "UF", "value": (facts.first("address") or {}).get("data", {}).get("state", "")} if facts.first("address") else None,
        {"label": "Domínios .br", "value": str(holder["data"].get("domains") or 0)} if holder else None,
        {"label": "Sanções", "value": str(len(sanctions)) if sanctions else ("nenhuma" if facts.value("sanction-check") else "")},
        {"label": "Contratos federais", "value": contract_summary["value"].split(" ")[0]} if contract_summary else None,
    ]
    result: dict[str, Any] = {
        "title": name or value,
        "subtitle": " · ".join(part for part in (facts.value("trade-name"), facts.value("formatted") or value) if part),
        "facts": [item for item in facts_line if item and item["value"]],
        "flags": flags,
        "sections": [section for section in sections if section],
    }
    place = facts.first("geolocation")
    point = _point((place or {}).get("data", {}).get("coordinates", ""), facts.value("address") or (place or {}).get("value", ""))
    if point:
        result["map"] = {**point, "precision": "CEP (aproximado)"}
    return result


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
        ], pivot=True),
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


def _meaning(facts: Facts, result_type: str) -> str:
    entry = facts.first(result_type)
    return str(entry["data"].get("meaning", "")) if entry else ""


CPF_NOTE = (
    "Um CPF carrega só isto: os dígitos verificadores e a região fiscal de emissão. Nome, nascimento, "
    "endereço e situação cadastral ficam na Receita Federal e não são consultados pelo GARBAGE."
)
PHONE_NOTE = (
    "Pelo número dá para saber país, DDD, estado e tipo de linha. A operadora atual não: com a portabilidade "
    "o prefixo deixou de indicar a operadora. O dono e a localização de quem usa o número não são consultados."
)


def _documents(query_type: str, value: str, facts: Facts) -> dict[str, Any]:
    validity = facts.value("validity")
    flags: list[dict[str, str]] = []
    if query_type == "cpf":
        region = facts.first("fiscal-region")
        check = facts.value("check-digits")
        if facts.value("warning"):
            flags.append({"level": "high", "text": "CPF com todos os dígitos iguais: inválido por regra."})
        elif validity == "inválido":
            flags.append({"level": "high", "text": f"CPF inválido: dígitos verificadores {check}."})
        rows = [
            _row("Formato", facts.value("formatted")),
            _row("Validade", validity, hint=_meaning(facts, "validity")),
            _row("Dígitos verificadores", check, hint=_meaning(facts, "check-digits")),
            _row("Região fiscal", region["value"] if region else "", hint=_meaning(facts, "fiscal-region")),
            _row("Estados da região", region["data"].get("states", "") if region else ""),
        ]
        subtitle = f"CPF {validity}" + (f" · emitido na região fiscal {region['value']}" if region else "")
        return {
            "title": facts.value("formatted") or value,
            "subtitle": subtitle,
            "facts": [fact for fact in (
                {"label": "Validade", "value": validity},
                {"label": "Região fiscal", "value": region["value"]} if region else None,
                {"label": "9º dígito", "value": region["data"].get("digit", "")} if region else None,
            ) if fact and fact["value"]],
            "flags": flags,
            "sections": [section for section in [
                _section("facts", "Verificação", rows),
                {"id": "limits", "title": "O que o número diz", "rows": [], "note": CPF_NOTE},
            ] if section],
        }

    line = facts.value("line-type")
    state = facts.first("state")
    ddd = facts.value("phone-region")
    country = facts.first("country")
    suggestion = facts.value("phone-suggestion")
    if validity == "formato não reconhecido":
        flags.append({"level": "high", "text": "Número com formato não reconhecido: confira DDD e quantidade de dígitos."})
    if suggestion:
        flags.append({"level": "medium", "text": f"Celular sem o 9: hoje ele seria {suggestion}."})
    if country and country["value"] != "Brasil":
        flags.append({"level": "info", "text": f"Número de fora do Brasil ({country['value']})."})
    rows = [
        _row("Tipo de linha", line, hint=_meaning(facts, "line-type")),
        _row("Serviço", facts.value("service")),
        _row("País", f"{country['value']} ({country['data'].get('calling_code', '')})" if country else ""),
        _row("DDD", ddd, hint=_meaning(facts, "phone-region")),
        _row("Estado", state["value"] if state else "", hint=_meaning(facts, "state")),
        _row("Com o 9", suggestion, hint=_meaning(facts, "phone-suggestion")),
    ]
    formats = [{"value": entry["value"], "meta": entry["data"].get("label", "")} for entry in facts.all("phone-format")]
    subtitle = " · ".join(part for part in (
        line.capitalize() if line else "",
        ddd.split(" · ")[0] if ddd else "",
        state["value"] if state else (country["value"] if country else ""),
    ) if part)
    return {
        "title": facts.value("formatted") or value,
        "subtitle": subtitle or "Telefone",
        "facts": [fact for fact in (
            {"label": "Tipo", "value": line},
            {"label": "DDD", "value": ddd.split(" · ")[0].replace("DDD ", "") if ddd else ""},
            {"label": "Estado", "value": state["value"] if state else ""},
            {"label": "País", "value": country["value"] if country else ""},
        ) if fact["value"]],
        "flags": flags,
        "sections": [section for section in [
            _section("facts", "Número", rows),
            _section("formats", "Como escrever e discar", items=formats),
            {"id": "limits", "title": "O que o número diz", "rows": [], "note": PHONE_NOTE},
        ] if section],
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
# URL, email, hashes, ASN, ranges, CVE


def _threat_reports(facts: Facts) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    count = facts.first("pulse-count")
    pulses = [
        {"value": entry["value"], "meta": _date(entry["data"].get("created", "")) + (f" · {entry['data']['adversary']}" if entry["data"].get("adversary") else "")}
        for entry in facts.all("pulse")
    ]
    return count, pulses


def _mail_rows(facts: Facts) -> tuple[list[dict[str, Any] | None], str, list[dict[str, str]]]:
    mx = sorted({re.sub(r"^\d+\s+", "", entry["value"]).rstrip(".") for entry in facts.all("dns-mx")})
    spf = next((entry["value"] for entry in facts.all("dns-txt") if entry["data"].get("policy") == "spf" or entry["value"].lower().startswith("v=spf1")), "")
    dmarc = facts.value("dns-dmarc")
    policy = (re.search(r"\bp=(\w+)", dmarc or "") or [None, ""])[1]
    provider = ""
    for marker, name in (("outlook.com", "Microsoft 365"), ("google.com", "Google Workspace"), ("googlemail.com", "Google Workspace"), ("zoho", "Zoho"), ("protonmail", "Proton Mail"), ("mimecast", "Mimecast"), ("pphosted", "Proofpoint"), ("secureserver.net", "GoDaddy"), ("locaweb", "Locaweb"), ("umbler", "Umbler"), ("hostinger", "Hostinger"), ("kinghost", "KingHost")):
        if marker in " ".join(mx).lower():
            provider = name
            break
    null_mx = any(entry["data"].get("null_mx") for entry in facts.all("dns-mx"))
    # Only say SPF/DMARC are missing when TXT records were actually asked for.
    txt_checked = bool(facts.all("dns-txt", "dns-dmarc"))
    flags: list[dict[str, str]] = []
    if not txt_checked:
        spf = dmarc = policy = ""
        mx_only = True
    else:
        mx_only = False
    if null_mx:
        flags.append({"level": "info", "text": "O domínio declara que não recebe e-mail (null MX)."})
    elif mx and not dmarc and not mx_only:
        flags.append({"level": "medium", "text": "Sem DMARC: fica mais fácil falsificar o remetente deste domínio."})
    elif policy == "none":
        flags.append({"level": "info", "text": "DMARC só observa (p=none); não bloqueia falsificações."})
    if mx and not spf and not null_mx and not mx_only:
        flags.append({"level": "medium", "text": "Sem SPF publicado."})
    rows = [
        _row("Provedor", provider),
        _row("Servidores MX", ", ".join(mx) or ("nenhum" if facts.all("dns-txt") else ""), sources=["dns-doh"]),
        _row("SPF", spf or ("não publicado" if mx and not mx_only else ""), sources=["dns-doh"]),
        _row("DMARC", dmarc or ("não publicado" if mx and not mx_only else ""), hint=f"política {policy}" if policy else "", sources=["dns-doh"]),
    ]
    return rows, provider, flags


def _url(value: str, facts: Facts) -> dict[str, Any]:
    from urllib.parse import urlsplit

    host = (urlsplit(value).hostname or "").lower()
    http = facts.first("http-response")
    title = facts.value("page-title")
    count, pulses = _threat_reports(facts)
    mail_rows, provider, mail_flags = _mail_rows(facts)
    validity = facts.first("cert-validity")
    days_left = (validity or {}).get("data", {}).get("days_remaining")
    present = {entry["value"] for entry in facts.all("security-header")}
    cookies = facts.all("cookie")
    insecure_cookies = [entry["value"] for entry in cookies if not entry["data"].get("secure") or not entry["data"].get("httponly")]
    scans = facts.all("scan")
    flags = list(mail_flags)
    if count and str(count["value"]) not in ("0", ""):
        flags.insert(0, {"level": "high", "text": f"Citada em {count['value']} relatório(s) de ameaça na AlienVault OTX."})
    if facts.all("malicious-url"):
        flags.insert(0, {"level": "high", "text": "Listada no URLhaus como distribuidora de malware."})
    if insecure_cookies:
        flags.append({"level": "info", "text": f"{len(insecure_cookies)} cookie(s) sem Secure ou HttpOnly."})
    sections = [
        _section("page", "Página", [
            _row("Título", title),
            _row("Endereço final", (http or {}).get("data", {}).get("final_url", "")),
            _row("Resposta HTTP", (http or {}).get("value", "")),
            _row("Redirecionamentos", " → ".join(entry["value"] for entry in facts.all("http-redirect"))),
            _row("Tecnologias", ", ".join(sorted({entry["value"] for entry in facts.all("technology")}))),
            _row("Cabeçalhos de segurança", f"{len(present)} presentes" if present else ""),
            _row("Cookies", ", ".join(entry["value"] for entry in cookies)),
            _row("Hash do favicon", facts.value("favicon"), hint="mmh3, igual ao do Shodan"),
        ]),
        _section("host", "Domínio", [
            _row("Domínio", host, pivot=True),
            _row("Servidor que respondeu", (http or {}).get("data", {}).get("address", ""), pivot=True),
        ], items=[{"value": entry["value"], "meta": ""} for entry in facts.all("dns-a", "dns-aaaa")], pivot=True),
        _section("mail", "E-mail do domínio", mail_rows),
        _section("tls", "Certificado TLS", [
            _row("Emitido para", facts.value("cert-subject")),
            _row("Emissor", (facts.first("cert-issuer") or {}).get("data", {}).get("organization", "")),
            _row("Validade", (validity or {}).get("value", "").replace("T", " ").replace("Z", ""), hint=f"{days_left} dia(s) restantes" if isinstance(days_left, int) else ""),
        ]),
        _section("security", "Contato de segurança", [
            _row("security.txt", {"published": "publicado", "not published": "não publicado"}.get(facts.value("security-txt"), facts.value("security-txt"))),
            _row("Contato", facts.value("security-contact-email", "security-contact-url", "security-contact")),
            _row("Política", facts.value("security-policy")),
        ]),
        _section("reputation", "Relatórios de ameaça", [
            _row("AlienVault OTX", f"{count['value']} relatório(s)" if count else ""),
            _row("Varreduras públicas (urlscan)", str(len(scans)) if scans else ""),
        ], items=pulses),
        _section("history", "Histórico", [
            _row("Primeira captura no Wayback", _date((facts.first("archive-summary") or {}).get("data", {}).get("first", ""))),
            _row("Capturas", facts.value("archive-summary").replace("distinct captures", "capturas distintas")),
        ]),
    ]
    return {
        "title": value,
        "subtitle": " · ".join(part for part in (title, provider and f"e-mail em {provider}") if part),
        "facts": [item for item in (
            {"label": "HTTP", "value": (http or {}).get("value", "")},
            {"label": "Domínio", "value": host},
            {"label": "Relatórios", "value": str(count["value"]) if count else ""},
        ) if item["value"]],
        "flags": flags,
        "sections": [section for section in sections if section],
    }


def _email(value: str, facts: Facts) -> dict[str, Any]:
    domain = value.rsplit("@", 1)[-1].lower()
    rows, provider, flags = _mail_rows(facts)
    events = {entry["data"].get("action", ""): entry["value"] for entry in facts.all("rdap-event")}
    created = events.get("registration") or events.get("registered") or ""
    age = _years_since(created)
    if age is not None and age < 1:
        flags.append({"level": "medium", "text": "O domínio do e-mail foi registrado há menos de um ano."})
    if not facts.all("dns-mx") and facts.all("dns-txt", "dns-ns"):
        flags.append({"level": "medium", "text": "O domínio não tem servidores MX: este endereço provavelmente não recebe e-mail."})
    sections = [
        _section("mail", "Configuração de e-mail do domínio", rows),
        _section("domain", "Domínio", [
            _row("Domínio", domain, pivot=True),
            _row("Situação", _status_text(facts)),
            _row("Criado em", _date(created), hint=f"há {age} ano(s)" if age else ""),
            _row("Expira em", _date(events.get("expiration", ""))),
            _row("Servidores de nome", ", ".join(sorted({entry["value"].rstrip(".") for entry in facts.all("dns-ns", "nameserver")}))),
        ]),
    ]
    return {
        "title": value,
        "subtitle": "Configuração pública do domínio. O GARBAGE não verifica se a caixa existe nem busca quem a usa.",
        "facts": [item for item in (
            {"label": "Domínio", "value": domain},
            {"label": "Provedor", "value": provider},
            {"label": "Criado", "value": _date(created)},
        ) if item["value"]],
        "flags": flags,
        "sections": [section for section in sections if section],
    }


def _hash(value: str, facts: Facts) -> dict[str, Any]:
    known = facts.first("known-file")
    count, pulses = _threat_reports(facts)
    # MalwareBazaar/ThreatFox signatures are families; OTX "families" are loose report tags.
    families = sorted({entry["value"] for entry in facts.all("signature", "malware")})
    tags = sorted({entry["value"] for entry in facts.all("malware-family")} - set(families))
    techniques = sorted({entry["value"] for entry in facts.all("attack-technique")})
    sample = facts.first("sample")
    detections = facts.first("detection-ratio", "detections")
    flags = []
    if (known or {}).get("data", {}).get("known_malicious"):
        flags.append({"level": "high", "text": f"Marcado como malicioso por {known['data']['known_malicious']} (CIRCL)."})
    if count and str(count["value"]) not in ("0", ""):
        flags.append({"level": "high", "text": f"Citado em {count['value']} relatório(s) de ameaça na AlienVault OTX."})
    if families:
        flags.append({"level": "high", "text": f"Ligado a {len(families)} família(s) de malware."})
    if known and not flags:
        flags.append({"level": "info", "text": "Arquivo conhecido de software distribuído (NSRL e outras bases)."})
    sections = [
        _section("file", "Arquivo", [
            _row("Nome conhecido", (known or {}).get("value", "")),
            _row("Produto", (known or {}).get("data", {}).get("product", "")),
            _row("Amostra", (sample or {}).get("value", "")),
            _row("Detecções", (detections or {}).get("value", "")),
        ]),
        _section("families", "Famílias de malware", items=[{"value": name, "meta": ""} for name in families]),
        _section("tags", "Etiquetas nos relatórios (OTX)", items=[{"value": name, "meta": ""} for name in tags]),
        _section("reports", "Relatórios de ameaça", [_row("AlienVault OTX", f"{count['value']} relatório(s)" if count else "")], items=pulses),
        _section("techniques", "Técnicas ATT&CK citadas nos relatórios", items=[{"value": item, "meta": ""} for item in techniques], pivot=True),
    ]
    return {
        "title": value,
        "subtitle": (known or {}).get("value", ""),
        "facts": [item for item in (
            {"label": "Relatórios", "value": str(count["value"]) if count else ""},
            {"label": "Famílias", "value": str(len(families)) if families else ""},
            {"label": "Técnicas", "value": str(len(techniques)) if techniques else ""},
        ) if item["value"]],
        "flags": flags,
        "sections": [section for section in sections if section],
    }


def _asn(value: str, facts: Facts) -> dict[str, Any]:
    holder = facts.value("as-holder") or facts.value("as-name") or facts.value("rdap-name")
    operator = facts.first("network-operator")
    data = (operator or {}).get("data", {})
    as_name = facts.first("as-name")
    prefixes = facts.all("announced-prefix")
    events = {entry["data"].get("action", ""): entry["value"] for entry in facts.all("rdap-event")}
    sections = [
        _section("holder", "Titular", [
            _row("Nome", holder),
            _row("Operador", (operator or {}).get("value", ""), sources=["peeringdb"]),
            _row("País", (as_name or {}).get("data", {}).get("country", "")),
            _row("Registro", str((as_name or {}).get("data", {}).get("registry", "")).upper()),
            _row("Alocado em", _date((as_name or {}).get("data", {}).get("allocated", "") or events.get("registration", ""))),
            _row("Contato de abuso", facts.value("abuse-contact")),
        ]),
        _section("peering", "Interconexão (PeeringDB)", [
            _row("Política de peering", data.get("policy", "")),
            _row("Pontos de troca", str(data.get("ix_count", "")) if data.get("ix_count") else ""),
            _row("Data centers", str(data.get("facility_count", "")) if data.get("facility_count") else ""),
            _row("Alcance", data.get("scope", "")),
            _row("Tipo de rede", data.get("info_type", "")),
            _row("AS-SET", data.get("irr_as_set", "")),
        ]),
        _section("prefixes", "Prefixos anunciados", items=[{"value": entry["value"], "meta": ""} for entry in prefixes], pivot=True,
                 note="Blocos de IP que este sistema autônomo anuncia hoje na internet (RIPEstat)."),
    ]
    return {
        "title": value.upper(),
        "subtitle": holder,
        "facts": [item for item in (
            {"label": "Prefixos", "value": str(len(prefixes)) if prefixes else ""},
            {"label": "Pontos de troca", "value": str(data.get("ix_count", "")) if data.get("ix_count") else ""},
            {"label": "País", "value": (as_name or {}).get("data", {}).get("country", "")},
        ) if item["value"]],
        "flags": [],
        "sections": [section for section in sections if section],
    }


def _cidr(value: str, facts: Facts) -> dict[str, Any]:
    origin = facts.first("origin-asn")
    owner = next((entry["value"] for entry in facts.all("organization") if entry["data"].get("role") == "registrant"), "") or facts.value("rdap-name")
    ip_range = facts.first("ip-range")
    sections = [
        _section("range", "Faixa", [
            _row("Intervalo", (ip_range or {}).get("value", "")),
            _row("Titular", owner),
            _row("Nome no registro", facts.value("rdap-name")),
            _row("País", (ip_range or {}).get("data", {}).get("country", "")),
            _row("Tipo", (ip_range or {}).get("data", {}).get("type", "")),
            _row("Contato de abuso", facts.value("abuse-contact")),
        ]),
        _section("routing", "Roteamento", [
            _row("Anunciado por", (origin or {}).get("value", ""), hint=(origin or {}).get("data", {}).get("holder", ""), pivot=True),
            _row("Prefixo anunciado", (origin or {}).get("data", {}).get("prefix", ""), pivot=True),
        ]),
    ]
    return {
        "title": value,
        "subtitle": owner,
        "facts": [item for item in ({"label": "ASN", "value": (origin or {}).get("value", "")}, {"label": "País", "value": (ip_range or {}).get("data", {}).get("country", "")}) if item["value"]],
        "flags": [],
        "sections": [section for section in sections if section],
    }


def _cve(value: str, facts: Facts) -> dict[str, Any]:
    epss = facts.first("epss")
    score = float(epss["value"]) if epss and re.match(r"^[\d.]+$", epss["value"]) else None
    percentile = (epss or {}).get("data", {}).get("percentile")
    kev = facts.first("kev-entry", "kev")
    record = facts.first("cve-record")
    record_data = (record or {}).get("data", {})
    cvss_data = record_data.get("cvss") or {}
    cvss = {"value": f"{cvss_data.get('score')} (CVSS {cvss_data.get('version')})", "data": {"severity": str(cvss_data.get("severity", "")).lower()}} if cvss_data.get("score") is not None else None
    description = record_data.get("description") or facts.value("summary")
    packages = facts.all("affected-package")
    count, pulses = _threat_reports(facts)
    families = sorted({entry["value"] for entry in facts.all("malware-family")})
    flags = []
    if kev or record_data.get("kev_due_date"):
        flags.append({"level": "high", "text": "Está no catálogo KEV da CISA: exploração confirmada."})
    if score is not None and score >= 0.5:
        flags.append({"level": "high", "text": f"EPSS {score:.0%}: alta chance de exploração nos próximos 30 dias."})
    elif score is not None and score >= 0.1:
        flags.append({"level": "medium", "text": f"EPSS {score:.0%}."})
    if facts.first("notice") and not kev and not record_data.get("kev_due_date"):
        flags.append({"level": "info", "text": "O catálogo KEV local não foi baixado; a ausência dele não diz nada."})
    sections = [
        _section("summary", "Resumo", [
            _row("Descrição", description),
            _row("CVSS", (cvss or {}).get("value", ""), hint=(cvss or {}).get("data", {}).get("severity", "")),
            _row("EPSS", f"{score:.1%}" if score is not None else "", hint=f"percentil {float(percentile):.0%}" if isinstance(percentile, (int, float)) else ""),
            _row("CISA KEV", "sim" if kev or record_data.get("kev_due_date") else "", hint=f"prazo {_date(record_data['kev_due_date'])}" if record_data.get("kev_due_date") else ""),
            _row("Fraqueza (CWE)", ", ".join(record_data.get("cwe") or [])),
            _row("Publicada em", _date(record_data.get("published", ""))),
            _row("Outros identificadores", ", ".join(entry["value"] for entry in facts.all("alias"))),
        ]),
        _section("packages", "Pacotes afetados", items=[
            {"value": entry["value"], "meta": ("corrigido em " + ", ".join(entry["data"].get("fixed_in") or [])) if entry["data"].get("fixed_in") else ""} for entry in packages
        ], note="Do OSV.dev; a lista de versões completa fica nos dados brutos."),
        _section("reports", "Relatórios de ameaça", [_row("AlienVault OTX", f"{count['value']} relatório(s)" if count else "")], items=pulses),
        _section("families", "Malware que usa esta falha", items=[{"value": name, "meta": ""} for name in families]),
    ]
    return {
        "title": value.upper(),
        "subtitle": description[:160],
        "facts": [item for item in (
            {"label": "EPSS", "value": f"{score:.0%}" if score is not None else ""},
            {"label": "KEV", "value": "sim" if kev else ""},
            {"label": "Pacotes", "value": str(len(packages)) if packages else ""},
            {"label": "Relatórios", "value": str(count["value"]) if count else ""},
        ) if item["value"]],
        "flags": flags,
        "sections": [section for section in sections if section],
    }


# ---------------------------------------------------------------------------


def _ransomware(body: dict[str, Any], facts: Facts) -> None:
    """Ransomware leak-site posts naming the organisation (group claims)."""
    victims = facts.all("ransomware-victim")
    mentions = facts.all("ransomware-mention")
    check = facts.first("ransomware-check")
    if not (victims or mentions or check):
        return

    def item(entry: dict[str, Any]) -> dict[str, str]:
        data = entry["data"]
        return {"value": entry["value"], "meta": " · ".join(part for part in (
            str(data.get("group") or ""), _date(data.get("attack_date", "")), str(data.get("country") or ""), str(data.get("match") or "")) if part)}

    section = _section(
        "ransomware",
        "Sites de vazamento de ransomware",
        [_row("Resultado", f"{len(victims)} post(s) com esta organização" if victims else "nenhum post com esta organização",
              hint=check["value"] if check else "", sources=["ransomware-live"])],
        items=[item(entry) for entry in victims] + [item(entry) for entry in mentions[:10]],
        note="Cada post é a alegação do grupo, não a confirmação de um ataque. Menções na descrição de outra vítima costumam ser clientes ou parceiros dela.",
    )
    if section:
        body.setdefault("sections", []).append(section)
    if victims:
        groups = sorted({entry["data"].get("group", "") for entry in victims if entry["data"].get("group")})
        body.setdefault("flags", []).insert(0, {"level": "high", "text": f"Aparece como vítima em site de ransomware ({', '.join(groups)})."})


def _phishing(body: dict[str, Any], facts: Facts) -> None:
    """Public phishing lists that name the value or names under it."""
    listed = facts.all("phishing-listed")
    under = facts.all("phishing-under")
    check = facts.first("phishing-check")
    if not (listed or under or check):
        return
    names = sorted({name for entry in under for name in entry["data"].get("names") or []})
    rows = [
        _row("Resultado", ", ".join(f"{entry['value']} ({entry['data'].get('match', '')})" for entry in listed) or "não listado",
             hint=f"conferidas: {', '.join(check['data'].get('checked') or [])}" if check else "", sources=["phishing-lists"]),
    ]
    section = _section("phishing", "Listas de phishing", rows, items=[{"value": name, "meta": "listado"} for name in names], pivot=True)
    if section:
        body.setdefault("sections", []).append(section)
    if listed:
        body.setdefault("flags", []).insert(0, {"level": "high", "text": f"Em lista pública de phishing: {', '.join(entry['value'] for entry in listed)}."})
    elif names:
        body.setdefault("flags", []).append({"level": "medium", "text": f"{len(names)} nome(s) abaixo deste domínio em listas de phishing."})


def _own_intel(body: dict[str, Any], facts: Facts) -> None:
    """What the analyst's own MISP and OpenCTI already hold about the value."""
    events = facts.all("misp-event")
    observables = facts.all("opencti-observable")
    reports = facts.all("opencti-report")
    items = [
        {"value": entry["value"], "meta": " · ".join(part for part in (
            "MISP", _date(entry["data"].get("date", "")), ", ".join(entry["data"].get("tags") or [])[:120]) if part)}
        for entry in events
    ] + [
        {"value": entry["value"], "meta": " · ".join(part for part in (
            "OpenCTI", f"pontuação {entry['data']['score']}" if entry["data"].get("score") is not None else "",
            ", ".join(entry["data"].get("labels") or [])[:120]) if part)}
        for entry in observables
    ] + [
        {"value": entry["value"], "meta": " · ".join(part for part in ("relatório no OpenCTI", _date(entry["data"].get("published", ""))) if part)}
        for entry in reports
    ]
    section = _section("own-intel", "Na sua base (MISP e OpenCTI)", items=items)
    if not section:
        return
    body.setdefault("sections", []).insert(0, section)
    parts = [f"{len(events)} evento(s) do seu MISP" if events else "", f"{len(observables) + len(reports)} registro(s) do seu OpenCTI" if observables or reports else ""]
    body.setdefault("flags", []).insert(0, {"level": "medium", "text": "Já aparece em " + " e ".join(part for part in parts if part) + "."})


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
    elif query_type == "url":
        body = _url(value, facts)
    elif query_type == "email":
        body = _email(value, facts)
    elif query_type in ("md5", "sha1", "sha256"):
        body = _hash(value, facts)
    elif query_type == "asn":
        body = _asn(value, facts)
    elif query_type == "cidr":
        body = _cidr(value, facts)
    elif query_type == "cve":
        body = _cve(value, facts)
    else:
        body = {"title": value, "subtitle": "", **_generic(facts, labels or {})}
    body.setdefault("title", value)
    body.setdefault("subtitle", "")
    _own_intel(body, facts)
    _phishing(body, facts)
    _ransomware(body, facts)
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
