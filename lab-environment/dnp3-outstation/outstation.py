#!/usr/bin/env python3
"""DNP3 outstation endpoint for the lab.

Runs a real opendnp3 outstation (via the ``dnp3-python`` bindings) exposing the
canonical point map. The link address is 10 and the expected master address is 3
(a non-authorized master, so control operations from it exercise the
``DNP3_UNAUTHORIZED_CONTROL`` detection while an authorized master would not).
"""
import logging
import os
import sys
import time

from pydnp3 import asiodnp3, asiopal, opendnp3, openpal

LOG_LEVELS = opendnp3.levels.NORMAL
LOCAL_IP = os.getenv("OT_DNP3_BIND", "0.0.0.0")
PORT = int(os.getenv("OT_DNP3_PORT", "20000"))
OUTSTATION_ADDR = int(os.getenv("OT_DNP3_OUTSTATION_ADDR", "10"))
MASTER_ADDR = int(os.getenv("OT_DNP3_MASTER_ADDR", "3"))

stdout_stream = logging.StreamHandler(sys.stdout)
stdout_stream.setFormatter(logging.Formatter("%(asctime)s\t%(levelname)s\t%(message)s"))
_log = logging.getLogger("dnp3-outstation")
_log.addHandler(stdout_stream)
_log.setLevel(logging.INFO)


class OutstationApplication(opendnp3.IOutstationApplication):
    def __init__(self):
        super().__init__()
        self.stack_config = self._configure_stack()
        self._configure_database(self.stack_config.dbConfig)
        self.manager = asiodnp3.DNP3Manager(1, asiodnp3.ConsoleLogger().Create())
        self.listener = AppChannelListener()
        self.channel = self.manager.AddTCPServer(
            "server",
            LOG_LEVELS,
            asiopal.ChannelRetry().Default(),
            LOCAL_IP,
            PORT,
            self.listener,
        )
        self.command_handler = OutstationCommandHandler()
        self.outstation = self.channel.AddOutstation(
            "outstation", self.command_handler, self, self.stack_config
        )
        self.outstation.Enable()

    def _configure_stack(self):
        stack_config = asiodnp3.OutstationStackConfig(opendnp3.DatabaseSizes.AllTypes(10))
        stack_config.outstation.eventBufferConfig = opendnp3.EventBufferConfig().AllTypes(10)
        stack_config.outstation.params.allowUnsolicited = True
        stack_config.link.LocalAddr = OUTSTATION_ADDR
        stack_config.link.RemoteAddr = MASTER_ADDR
        stack_config.link.KeepAliveTimeout = openpal.TimeDuration().Max()
        return stack_config

    def _configure_database(self, db_config):
        for index in range(0, 7):
            db_config.analog[index].clazz = opendnp3.PointClass.Class1
            db_config.analog[index].svariation = opendnp3.StaticAnalogVariation.Group30Var1
            db_config.analog[index].evariation = opendnp3.EventAnalogVariation.Group32Var7
            db_config.binary[index].clazz = opendnp3.PointClass.Class1
            db_config.binary[index].svariation = opendnp3.StaticBinaryVariation.Group1Var2
            db_config.binary[index].evariation = opendnp3.EventBinaryVariation.Group2Var2

    def ColdRestartSupport(self):
        return opendnp3.RestartMode.SUPPORTED

    def WarmRestartSupport(self):
        return opendnp3.RestartMode.SUPPORTED

    def GetApplicationIIN(self):
        return opendnp3.ApplicationIIN()

    def SupportsAssignClass(self):
        return True

    def SupportsWriteAbsoluteTime(self):
        return False

    def SupportsWriteTimeAndInterval(self):
        return False

    def shutdown(self):
        self.manager.Shutdown()


class OutstationCommandHandler(opendnp3.ICommandHandler):
    def Start(self):
        _log.info("command handler start")

    def End(self):
        _log.info("command handler end")

    def Select(self, command, index):
        _log.info("SELECT index=%s command=%s", index, command)
        return opendnp3.CommandStatus.SUCCESS

    def Operate(self, command, index, op_type):
        _log.info("OPERATE index=%s command=%s", index, command)
        return opendnp3.CommandStatus.SUCCESS


class AppChannelListener(asiodnp3.IChannelListener):
    def OnStateChange(self, state):
        _log.info("channel state=%s", state)


def main():
    app = OutstationApplication()
    print(
        f"DNP3 outstation listening on {LOCAL_IP}:{PORT} "
        f"(local={OUTSTATION_ADDR}, master={MASTER_ADDR})",
        flush=True,
    )
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        app.shutdown()


if __name__ == "__main__":
    main()
