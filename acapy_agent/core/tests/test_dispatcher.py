import json
from typing import Optional
from unittest import IsolatedAsyncioTestCase

import pytest
from marshmallow import EXCLUDE

from ...cache.base import BaseCache
from ...cache.in_memory import InMemoryCache
from ...config.injection_context import InjectionContext
from ...core.event_bus import EventBus
from ...core.protocol_registry import ProtocolRegistry
from ...messaging.agent_message import AgentMessage, AgentMessageSchema
from ...messaging.request_context import RequestContext
from ...protocols.coordinate_mediation.v1_0.route_manager import RouteManager
from ...protocols.didcomm_prefix import DIDCommPrefix
from ...protocols.issue_credential.v2_0.message_types import CRED_20_PROBLEM_REPORT
from ...protocols.issue_credential.v2_0.messages.cred_problem_report import (
    V20CredProblemReport,
)
from ...protocols.problem_report.v1_0.message import ProblemReport
from ...tests import mock
from ...transport.inbound.message import InboundMessage
from ...transport.inbound.receipt import MessageReceipt
from ...transport.outbound.message import OutboundMessage
from ...utils.stats import Collector
from ...utils.testing import create_test_profile
from .. import dispatcher as test_module


def make_inbound(payload) -> InboundMessage:
    return InboundMessage(payload, MessageReceipt(thread_id="dummy-thread"))


class Receiver:
    def __init__(self):
        self.messages = []

    async def send(
        self,
        context: InjectionContext,
        message: OutboundMessage,
        inbound: Optional[InboundMessage] = None,
    ):
        self.messages.append((context, message, inbound))


class StubAgentMessage(AgentMessage):
    class Meta:
        handler_class = "StubAgentMessageHandler"
        schema_class = "StubAgentMessageSchema"
        message_type = "doc/proto-name/1.1/message-type"


class StubAgentMessageSchema(AgentMessageSchema):
    class Meta:
        model_class = StubAgentMessage
        unknown = EXCLUDE


class StubAgentMessageHandler:
    async def handle(self, context, responder):
        pass


class StubV1_2AgentMessage(AgentMessage):
    class Meta:
        handler_class = "StubV1_2AgentMessageHandler"
        schema_class = "StubV1_2AgentMessageSchema"
        message_type = "doc/proto-name/1.2/message-type"


class StubV1_2AgentMessageSchema(AgentMessageSchema):
    class Meta:
        model_class = StubV1_2AgentMessage
        unknonw = EXCLUDE


class StubV1_2AgentMessageHandler:
    async def handle(self, context, responder):
        pass


class TestDispatcher(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile()
        self.profile.context.injector.bind_instance(ProtocolRegistry, ProtocolRegistry())
        self.profile.context.injector.bind_instance(Collector, Collector())
        self.profile.context.injector.bind_instance(EventBus, EventBus())
        self.profile.context.injector.bind_instance(RouteManager, mock.MagicMock())

    async def test_dispatch(self):
        profile = self.profile
        registry = profile.inject(ProtocolRegistry)
        registry.register_message_types(
            {
                pfx.qualify(StubAgentMessage.Meta.message_type): StubAgentMessage
                for pfx in DIDCommPrefix
            }
        )
        dispatcher = test_module.Dispatcher(profile)
        await dispatcher.setup()
        rcv = Receiver()
        message = {
            "@type": DIDCommPrefix.qualify_current(StubAgentMessage.Meta.message_type)
        }

        with (
            mock.patch.object(
                StubAgentMessageHandler, "handle", autospec=True
            ) as handler_mock,
            mock.patch.object(
                test_module, "BaseConnectionManager", autospec=True
            ) as conn_mgr_mock,
        ):
            conn_mgr_mock.return_value = mock.MagicMock(
                find_inbound_connection=mock.CoroutineMock(
                    return_value=mock.MagicMock(connection_id="dummy")
                )
            )
            await dispatcher.queue_message(
                dispatcher.profile, make_inbound(message), rcv.send
            )
            await dispatcher.task_queue
            handler_mock.assert_awaited_once()
            assert isinstance(handler_mock.call_args[0][1].message, StubAgentMessage)
            assert isinstance(
                handler_mock.call_args[0][2], test_module.DispatcherResponder
            )

    async def test_dispatch_versioned_message(self):
        profile = self.profile
        registry = profile.inject(ProtocolRegistry)
        registry.register_message_types(
            {
                DIDCommPrefix.qualify_current(
                    StubAgentMessage.Meta.message_type
                ): StubAgentMessage
            },
            version_definition={
                "major_version": 1,
                "minimum_minor_version": 0,
                "current_minor_version": 1,
                "path": "v1_1",
            },
        )
        dispatcher = test_module.Dispatcher(profile)
        await dispatcher.setup()
        rcv = Receiver()
        message = {
            "@type": DIDCommPrefix.qualify_current(StubAgentMessage.Meta.message_type)
        }

        with (
            mock.patch.object(
                StubAgentMessageHandler, "handle", autospec=True
            ) as handler_mock,
            mock.patch.object(test_module, "BaseConnectionManager", autospec=True),
        ):
            await dispatcher.queue_message(
                dispatcher.profile, make_inbound(message), rcv.send
            )
            await dispatcher.task_queue
            handler_mock.assert_awaited_once()
            assert isinstance(handler_mock.call_args[0][1].message, StubAgentMessage)
            assert isinstance(
                handler_mock.call_args[0][2], test_module.DispatcherResponder
            )

    @pytest.mark.skip("This test is not completing")
    async def test_dispatch_versioned_message_no_message_class(self):
        registry = self.profile.inject(ProtocolRegistry)
        registry.register_message_types(
            {
                DIDCommPrefix.qualify_current(
                    StubAgentMessage.Meta.message_type
                ): StubAgentMessage
            },
            version_definition={
                "major_version": 1,
                "minimum_minor_version": 0,
                "current_minor_version": 1,
                "path": "v1_1",
            },
        )
        dispatcher = test_module.Dispatcher(self.profile)
        await dispatcher.setup()
        rcv = Receiver()
        message = {"@type": "doc/proto-name/1.1/no-such-message-type"}

        with mock.patch.object(StubAgentMessageHandler, "handle", autospec=True):
            await dispatcher.queue_message(
                dispatcher.profile, make_inbound(message), rcv.send
            )
            await dispatcher.task_queue
            assert rcv.messages and isinstance(rcv.messages[0][1], OutboundMessage)
            payload = json.loads(rcv.messages[0][1].payload)
            assert payload["@type"] == DIDCommPrefix.qualify_current(
                ProblemReport.Meta.message_type
            )

    @pytest.mark.skip("This test is not completing")
    async def test_dispatch_versioned_message_message_class_deserialize_x(self):
        profile = self.profile
        registry = profile.inject(ProtocolRegistry)
        registry.register_message_types(
            {
                DIDCommPrefix.qualify_current(
                    StubAgentMessage.Meta.message_type
                ): StubAgentMessage
            },
            version_definition={
                "major_version": 1,
                "minimum_minor_version": 0,
                "current_minor_version": 1,
                "path": "v1_1",
            },
        )
        dispatcher = test_module.Dispatcher(profile)
        await dispatcher.setup()
        rcv = Receiver()
        message = {"@type": "doc/proto-name/1.1/no-such-message-type"}

        with (
            mock.patch.object(StubAgentMessageHandler, "handle", autospec=True),
            mock.patch.object(
                registry, "resolve_message_class", mock.MagicMock()
            ) as mock_resolve,
        ):
            mock_resolve.return_value = mock.MagicMock(
                deserialize=mock.MagicMock(side_effect=test_module.BaseModelError())
            )
            await dispatcher.queue_message(
                dispatcher.profile, make_inbound(message), rcv.send
            )
            await dispatcher.task_queue
            assert rcv.messages and isinstance(rcv.messages[0][1], OutboundMessage)
            payload = json.loads(rcv.messages[0][1].payload)
            assert payload["@type"] == DIDCommPrefix.qualify_current(
                ProblemReport.Meta.message_type
            )

    async def test_dispatch_versioned_message_handle_greater_succeeds(self):
        profile = self.profile
        registry = profile.inject(ProtocolRegistry)
        registry.register_message_types(
            {
                DIDCommPrefix.qualify_current(
                    StubAgentMessage.Meta.message_type
                ): StubAgentMessage
            },
            version_definition={
                "major_version": 1,
                "minimum_minor_version": 0,
                "current_minor_version": 1,
                "path": "v1_1",
            },
        )
        dispatcher = test_module.Dispatcher(profile)
        await dispatcher.setup()
        rcv = Receiver()
        message = {
            "@type": DIDCommPrefix.qualify_current(StubV1_2AgentMessage.Meta.message_type)
        }

        with (
            mock.patch.object(
                StubAgentMessageHandler, "handle", autospec=True
            ) as handler_mock,
            mock.patch.object(test_module, "BaseConnectionManager", autospec=True),
        ):
            await dispatcher.queue_message(
                dispatcher.profile, make_inbound(message), rcv.send
            )
            await dispatcher.task_queue
            handler_mock.assert_awaited_once()
            assert isinstance(handler_mock.call_args[0][1].message, StubAgentMessage)
            assert isinstance(
                handler_mock.call_args[0][2], test_module.DispatcherResponder
            )

    @pytest.mark.skip("This test is not completing")
    async def test_dispatch_versioned_message_fail(self):
        profile = self.profile
        registry = profile.inject(ProtocolRegistry)
        registry.register_message_types(
            {
                DIDCommPrefix.qualify_current(
                    StubV1_2AgentMessage.Meta.message_type
                ): StubV1_2AgentMessage
            },
            version_definition={
                "major_version": 1,
                "minimum_minor_version": 2,
                "current_minor_version": 2,
                "path": "v1_2",
            },
        )
        dispatcher = test_module.Dispatcher(profile)
        await dispatcher.setup()
        rcv = Receiver()
        message = {
            "@type": DIDCommPrefix.qualify_current(StubAgentMessage.Meta.message_type)
        }

        with mock.patch.object(StubAgentMessageHandler, "handle", autospec=True):
            await dispatcher.queue_message(
                dispatcher.profile, make_inbound(message), rcv.send
            )
            await dispatcher.task_queue
            assert rcv.messages and isinstance(rcv.messages[0][1], OutboundMessage)
            payload = json.loads(rcv.messages[0][1].payload)
            assert payload["@type"] == DIDCommPrefix.qualify_current(
                ProblemReport.Meta.message_type
            )

    @pytest.mark.skip("This test is not completing")
    async def test_bad_message_dispatch_parse_x(self):
        dispatcher = test_module.Dispatcher(self.profile)
        await dispatcher.setup()
        rcv = Receiver()
        bad_messages = ["not even a dict", {"bad": "message"}]
        for bad in bad_messages:
            await dispatcher.queue_message(
                dispatcher.profile, make_inbound(bad), rcv.send
            )
            await dispatcher.task_queue
            assert rcv.messages and isinstance(rcv.messages[0][1], OutboundMessage)
            payload = json.loads(rcv.messages[0][1].payload)
            assert payload["@type"] == DIDCommPrefix.qualify_current(
                ProblemReport.Meta.message_type
            )
            rcv.messages.clear()

    async def test_bad_message_dispatch_problem_report_x(self):
        profile = self.profile
        registry = profile.inject(ProtocolRegistry)
        registry.register_message_types(
            {
                pfx.qualify(CRED_20_PROBLEM_REPORT): V20CredProblemReport
                for pfx in DIDCommPrefix
            }
        )
        dispatcher = test_module.Dispatcher(profile)
        await dispatcher.setup()
        rcv = Receiver()
        bad_message = {
            "@type": DIDCommPrefix.qualify_current(CRED_20_PROBLEM_REPORT),
            "description": "should be a dict",
        }
        await dispatcher.queue_message(
            dispatcher.profile, make_inbound(bad_message), rcv.send
        )
        await dispatcher.task_queue
        assert not rcv.messages

    async def test_dispatch_log(self):
        profile = self.profile
        registry = profile.inject(ProtocolRegistry)
        registry.register_message_types(
            {
                DIDCommPrefix.qualify_current(
                    StubAgentMessage.Meta.message_type
                ): StubAgentMessage
            },
        )

        dispatcher = test_module.Dispatcher(profile)
        await dispatcher.setup()

        exc = KeyError("sample exception")
        mock_task = mock.MagicMock(
            exc_info=(type(exc), exc, exc.__traceback__),
            ident="abc",
            timing={
                "queued": 1234567890,
                "unqueued": 1234567899,
                "started": 1234567901,
                "ended": 1234567999,
            },
        )
        dispatcher.log_task(mock_task)

    async def test_create_send_outbound(self):
        profile = self.profile
        context = RequestContext(
            profile,
            settings={"timing.enabled": True},
        )
        registry = profile.inject(ProtocolRegistry)
        registry.register_message_types(
            {
                pfx.qualify(StubAgentMessage.Meta.message_type): StubAgentMessage
                for pfx in DIDCommPrefix
            }
        )
        message = StubAgentMessage()
        responder = test_module.DispatcherResponder(context, message, None)
        outbound_message = await responder.create_outbound(
            json.dumps(message.serialize())
        )
        with (
            mock.patch.object(responder, "_send", mock.CoroutineMock()),
            mock.patch.object(
                test_module.BaseResponder,
                "conn_rec_active_state_check",
                mock.CoroutineMock(return_value=True),
            ),
        ):
            await responder.send_outbound(outbound_message)

    async def test_create_send_outbound_with_msg_attrs(self):
        profile = self.profile
        context = RequestContext(
            profile,
            settings={"timing.enabled": True},
        )
        registry = profile.inject(ProtocolRegistry)
        registry.register_message_types(
            {
                pfx.qualify(StubAgentMessage.Meta.message_type): StubAgentMessage
                for pfx in DIDCommPrefix
            }
        )
        message = StubAgentMessage()
        responder = test_module.DispatcherResponder(context, message, None)
        outbound_message = await responder.create_outbound(message)
        with (
            mock.patch.object(responder, "_send", mock.CoroutineMock()),
            mock.patch.object(
                test_module.BaseResponder,
                "conn_rec_active_state_check",
                mock.CoroutineMock(return_value=True),
            ),
        ):
            await responder.send_outbound(
                message=outbound_message,
                message_type=message._message_type,
                message_id=message._id,
            )

    async def test_create_send_outbound_with_msg_attrs_x(self):
        profile = self.profile
        context = RequestContext(
            profile,
            settings={"timing.enabled": True},
        )
        registry = profile.inject(ProtocolRegistry)
        registry.register_message_types(
            {
                pfx.qualify(StubAgentMessage.Meta.message_type): StubAgentMessage
                for pfx in DIDCommPrefix
            }
        )
        message = StubAgentMessage()
        responder = test_module.DispatcherResponder(context, message, None)
        outbound_message = await responder.create_outbound(message)
        outbound_message.connection_id = "123"
        with mock.patch.object(
            test_module.BaseResponder,
            "conn_rec_active_state_check",
            mock.CoroutineMock(return_value=False),
        ):
            with self.assertRaises(RuntimeError):
                await responder.send_outbound(
                    message=outbound_message,
                    message_type=message._message_type,
                    message_id=message._id,
                )

    async def test_create_send_webhook(self):
        profile = self.profile
        context = RequestContext(profile)
        message = StubAgentMessage()
        responder = test_module.DispatcherResponder(context, message, None)
        with pytest.deprecated_call():
            await responder.send_webhook("topic", {"pay": "load"})

    async def test_conn_rec_active_state_check_a(self):
        profile = self.profile
        profile.context.injector.bind_instance(BaseCache, InMemoryCache())
        context = RequestContext(profile)
        message = StubAgentMessage()
        responder = test_module.DispatcherResponder(context, message, None)
        with mock.patch.object(
            test_module.ConnRecord, "retrieve_by_id", mock.CoroutineMock()
        ) as mock_conn_ret_by_id:
            conn_rec = test_module.ConnRecord()
            conn_rec.state = test_module.ConnRecord.State.COMPLETED
            mock_conn_ret_by_id.return_value = conn_rec
            check_flag = await responder.conn_rec_active_state_check(
                profile,
                "conn-id",
            )
            assert check_flag
            check_flag = await responder.conn_rec_active_state_check(
                profile,
                "conn-id",
            )
            assert check_flag

    async def test_conn_rec_active_state_check_b(self):
        profile = self.profile
        profile.context.injector.bind_instance(BaseCache, InMemoryCache())
        profile.context.injector.bind_instance(
            EventBus, mock.MagicMock(notify=mock.CoroutineMock())
        )
        context = RequestContext(profile)
        message = StubAgentMessage()
        responder = test_module.DispatcherResponder(context, message, None)
        with mock.patch.object(
            test_module.ConnRecord, "retrieve_by_id", mock.CoroutineMock()
        ) as mock_conn_ret_by_id:
            conn_rec_a = test_module.ConnRecord()
            conn_rec_a.state = test_module.ConnRecord.State.REQUEST
            conn_rec_b = test_module.ConnRecord()
            conn_rec_b.state = test_module.ConnRecord.State.COMPLETED
            mock_conn_ret_by_id.side_effect = [conn_rec_a, conn_rec_b]
            check_flag = await responder.conn_rec_active_state_check(
                profile,
                "conn-id",
            )
            assert check_flag

    async def test_create_enc_outbound(self):
        profile = self.profile
        context = RequestContext(profile)
        message = StubAgentMessage()
        responder = test_module.DispatcherResponder(context, message, None)
        with mock.patch.object(
            responder, "send_outbound", mock.CoroutineMock()
        ) as mock_send_outbound:
            await responder.send(message)
            mock_send_outbound.assert_called_once()
        msg_json = json.dumps(StubAgentMessage().serialize())
        message = msg_json.encode("utf-8")
        with mock.patch.object(
            responder, "send_outbound", mock.CoroutineMock()
        ) as mock_send_outbound:
            await responder.send(message)

        message = StubAgentMessage()
        with mock.patch.object(
            responder, "send_outbound", mock.CoroutineMock()
        ) as mock_send_outbound:
            await responder.send_reply(message)
            mock_send_outbound.assert_called_once()

        message = json.dumps(StubAgentMessage().serialize())
        with mock.patch.object(
            responder, "send_outbound", mock.CoroutineMock()
        ) as mock_send_outbound:
            await responder.send_reply(message)

    async def test_expired_context_x(self):
        def _smaller_scope():
            profile = self.profile
            context = RequestContext(profile)
            message = b"abc123xyz7890000"
            return test_module.DispatcherResponder(context, message, None)

        responder = _smaller_scope()
        with self.assertRaises(RuntimeError):
            await responder.create_outbound(b"test")

        with self.assertRaises(RuntimeError):
            await responder.send_outbound(None)

        with pytest.deprecated_call():
            with self.assertRaises(RuntimeError):
                await responder.send_webhook("test", {})
