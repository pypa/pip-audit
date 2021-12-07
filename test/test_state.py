import pretend  # type: ignore

from pip_audit import _state as state


def test_auditstate():
    class DummyActor(state._StateActor):
        update_state = pretend.call_recorder(lambda self, message: None)
        initialize = pretend.call_recorder(lambda self: None)
        finalize = pretend.call_recorder(lambda self: None)

    actor = DummyActor()
    with state.AuditState(members=[actor]) as s:
        s.update_state("hello")

    assert DummyActor.update_state.calls == [pretend.call(actor, "hello")]
    assert DummyActor.initialize.calls == [pretend.call(actor)]
    assert DummyActor.finalize.calls == [pretend.call(actor)]
