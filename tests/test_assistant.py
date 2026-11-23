"""The AI assistant: conversation loop, tools, confirmations and limits."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from garbage_intel import assistant, intel
from garbage_intel.db import initialize
from garbage_intel.entities import create_entity, list_entities
from garbage_intel.errors import ValidationError
from garbage_intel.intel import Connector, Finding, register_connector, unregister_connector
from garbage_intel.intel_keys import set_key
from garbage_intel.net import FetchResult
from garbage_intel.store import list_investigations
from garbage_intel.workspace import update_settings

KEY = "sk-or-v1-0123456789abcdef0123456789abcdef"


def reply(content="", calls=()):
    tool_calls = [
        {"id": f"call-{index}", "type": "function", "function": {"name": name, "arguments": json.dumps(arguments)}}
        for index, (name, arguments) in enumerate(calls)
    ]
    return {"choices": [{"message": {"role": "assistant", "content": content, "tool_calls": tool_calls or None}}]}


class AssistantTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.database = str(Path(self.directory.name) / "assistant.sqlite3")
        initialize(self.database)
        # Searches stay on local connectors.
        update_settings(self.database, {"intel.allow_network": False})
        intel.RATE_LIMITER.reset()
        self.replies = []
        self.requests = []
        original_fetch, original_start = assistant.FETCH, assistant.START

        def fetch(url, **kwargs):
            self.requests.append({"url": url, **kwargs})
            status, payload = self.replies.pop(0)
            body = json.dumps(payload).encode()
            return FetchResult(url=url, final_url=url, status=status, headers={}, body=body, sha256="", address="", elapsed_ms=1)

        assistant.FETCH = fetch
        assistant.START = lambda work: work()
        self.addCleanup(setattr, assistant, "FETCH", original_fetch)
        self.addCleanup(setattr, assistant, "START", original_start)

    def ready(self):
        set_key(self.database, "ai", KEY)
        assistant.set_model(self.database, "example/model-1")

    def roles(self, conversation):
        return [message["role"] for message in conversation["messages"]]

    def test_needs_a_key_and_a_model(self):
        with self.assertRaises(ValidationError):
            assistant.start_conversation(self.database, "oi")
        set_key(self.database, "ai", KEY)
        with self.assertRaises(ValidationError):
            assistant.start_conversation(self.database, "oi")
        with self.assertRaises(ValidationError):
            assistant.set_model(self.database, "not a model; drop")
        status = assistant.status(self.database)
        self.assertTrue(status["configured"])
        self.assertNotIn(KEY, json.dumps(status))

    def test_tools_run_and_are_logged(self):
        self.ready()
        self.replies = [
            (200, reply("Vou criar.", [
                ("create_case", {"name": "Phishing banco", "objective": "Mapear domínios"}),
                ("write_file", {"name": "notas.md", "content": "# Notas\n"}),
                ("open_screen", {"screen": "graph"}),
            ])),
            (200, reply("Pronto: caso criado e notas salvas.")),
        ]
        conversation = assistant.start_conversation(self.database, "Cria um caso", {"view": "overview", "params": []})
        self.assertEqual(conversation["status"], "idle")
        self.assertEqual(self.roles(conversation), ["user", "assistant", "tool", "tool", "tool", "assistant"])
        self.assertEqual([case["name"] for case in list_investigations(self.database)], ["Phishing banco"])
        self.assertEqual(assistant.read_file(self.database, "notas.md"), "# Notas\n")
        tools = [message for message in conversation["messages"] if message["role"] == "tool"]
        self.assertEqual([tool["action"]["status"] for tool in tools], ["done", "done", "done"])
        self.assertEqual(tools[2]["action"]["ui"], {"type": "open", "view": "graph", "params": []})
        first = self.requests[0]
        self.assertEqual(first["headers"]["Authorization"], f"Bearer {KEY}")
        self.assertEqual(first["allowed_hosts"], ("openrouter.ai",))
        sent = json.loads(first["body"])
        self.assertEqual(sent["model"], "example/model-1")
        self.assertEqual(sent["messages"][0]["role"], "system")
        self.assertIn("[Tela aberta: overview]", sent["messages"][1]["content"])
        second = json.loads(self.requests[1]["body"])["messages"]
        self.assertEqual([item["role"] for item in second[-4:]], ["assistant", "tool", "tool", "tool"])
        self.assertNotIn(KEY, json.dumps(assistant.get_conversation(self.database, conversation["id"])))

    def test_deleting_waits_for_the_analyst(self):
        self.ready()
        entity = create_entity(self.database, entity_type="domain", name="example.org", identifier="example.org")
        self.replies = [(200, reply("", [("delete_entity", {"entity_id": entity["id"]})])), (200, reply("Ok, não apaguei."))]
        conversation = assistant.start_conversation(self.database, "apaga example.org")
        self.assertEqual(conversation["status"], "waiting")
        pending = conversation["messages"][-1]
        self.assertEqual(pending["action"]["status"], "pending")
        self.assertIn("example.org", pending["action"]["summary"])
        with self.assertRaises(Exception):
            assistant.send_message(self.database, conversation["id"], "e aí?")
        done = assistant.confirm(self.database, conversation["id"], pending["id"], False)
        self.assertEqual(done["status"], "idle")
        self.assertEqual(done["messages"][2]["action"]["status"], "declined")
        self.assertEqual(list_entities(self.database)["total"], 1)

        self.replies = [(200, reply("", [("delete_entity", {"entity_id": entity["id"]})])), (200, reply("Apaguei."))]
        again = assistant.send_message(self.database, conversation["id"], "pode apagar")
        approved = assistant.confirm(self.database, conversation["id"], again["messages"][-1]["id"], True)
        self.assertEqual(approved["messages"][-2]["action"]["status"], "done")
        self.assertEqual(list_entities(self.database)["total"], 0)

    def test_scope_limits_hold(self):
        self.ready()
        self.replies = [
            (200, reply("", [
                ("create_entity", {"entity_type": "person", "name": "Fulano"}),
                ("search_artifact", {"value": "Fulano de Tal"}),
                ("write_file", {"name": "../fora.md", "content": "x"}),
                ("write_file", {"name": "script.py", "content": "x"}),
                ("not_a_tool", {}),
            ])),
            (200, reply("Isso está fora do escopo.")),
        ]
        conversation = assistant.start_conversation(self.database, "procura a pessoa Fulano")
        tools = [message for message in conversation["messages"] if message["role"] == "tool"]
        self.assertEqual([tool["action"]["status"] for tool in tools], ["error"] * 5)
        self.assertEqual(list_entities(self.database)["total"], 0)
        self.assertFalse((Path(self.directory.name) / "fora.md").exists())
        self.assertEqual(assistant.list_files(self.database)["total"], 0)

    def test_search_returns_the_dossier(self):
        self.ready()
        register_connector(Connector("test-dns", "DNS", "test", ("domain",), lambda context: [Finding("subdomain", "mail.example.org")]))
        self.addCleanup(unregister_connector, "test-dns")
        self.replies = [(200, reply("", [("search_artifact", {"value": "example.org"})])), (200, reply("Achei 1 subdomínio."))]
        conversation = assistant.start_conversation(self.database, "pesquisa example.org")
        tool = conversation["messages"][2]
        self.assertEqual(tool["action"]["status"], "done")
        self.assertTrue(tool["action"]["link"].startswith("#/multisearch/"))
        result = json.loads(json.loads(self.requests[1]["body"])["messages"][-1]["content"])
        self.assertEqual(result["value"], "example.org")
        self.assertIn("mail.example.org", json.dumps(result))

    def test_new_tools_email_graph_and_confirmed_live_check(self):
        self.ready()
        register_connector(Connector("test-dns", "DNS", "test", ("domain",), lambda context: [Finding("subdomain", "mail.example.org")]))
        self.addCleanup(unregister_connector, "test-dns")
        run = intel.run_query(self.database, value="example.org", wait=True)
        raw = "From: \"suporte@banco.example\" <x@golpe.example>\nTo: a@example.org\nSubject: Oi\nReceived: from a (a [45.33.32.156]) by b; Sat, 14 Nov 2026 10:00:00 -0300\n\ncorpo"
        self.replies = [
            (200, reply("", [
                ("analyze_email", {"raw": raw}),
                ("add_to_graph", {"run_id": run["id"], "value": "mail.example.org", "section": "Subdomínios"}),
                ("live_check_url", {"url": "https://example.org"}),
            ])),
            (200, reply("Pronto.")),
        ]
        conversation = assistant.start_conversation(self.database, "analisa e verifica")
        tools = [message for message in conversation["messages"] if message["role"] == "tool"]
        self.assertEqual([tool["action"]["status"] for tool in tools], ["done", "done", "pending"])
        self.assertIn("vai ver o seu IP", tools[2]["action"]["summary"])
        sent = json.loads(self.requests[0]["body"])
        self.assertIn("live_check_url", {tool["function"]["name"] for tool in sent["tools"]})
        from garbage_intel.modules import live_check

        update_settings(self.database, {"intel.allow_network": True})  # a live check needs the network on
        with patch.object(live_check, "check", lambda url, **options: ({"url": url, "final_url": url, "final_status": 200, "hops": [{}], "flags": [], "page": None, "screenshot": None}, None)):
            done = assistant.confirm(self.database, conversation["id"], tools[2]["id"], True)
        self.assertEqual(done["messages"][-2]["action"]["status"], "done")
        self.assertEqual(len(list_entities(self.database)["items"]), 2)

    def test_provider_errors_end_the_run_without_the_key(self):
        self.ready()
        self.replies = [(401, {"error": {"message": f"bad key {KEY}"}})]
        conversation = assistant.start_conversation(self.database, "oi")
        self.assertEqual(conversation["status"], "error")
        self.assertIn("refused the key", conversation["error"])
        self.assertNotIn(KEY, conversation["error"])

    def test_step_limit(self):
        self.ready()
        self.replies = [(200, reply("", [("list_cases", {})]))] * assistant.MAX_STEPS
        conversation = assistant.start_conversation(self.database, "loop")
        self.assertEqual(len(self.requests), assistant.MAX_STEPS)
        self.assertIn("Parei", conversation["messages"][-1]["content"])

    def test_history_window_opens_on_a_user_message(self):
        rows = [
            {"role": "tool", "tool_call_id": "a", "content": "x", "action_json": "", "tool_calls_json": ""},
            {"role": "user", "content": "oi", "action_json": "", "tool_calls_json": ""},
        ]
        messages = assistant._model_messages(rows)
        self.assertEqual([item["role"] for item in messages], ["system", "user"])


if __name__ == "__main__":
    unittest.main()
