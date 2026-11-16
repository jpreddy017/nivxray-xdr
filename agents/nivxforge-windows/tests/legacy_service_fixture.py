"""SCM fixture, not a sensor; only used in isolated Windows migration CI."""
import servicemanager
import win32event
import win32service
import win32serviceutil
class Fixture(win32serviceutil.ServiceFramework):
    _svc_name_='NivXForgeSensor'
    _svc_display_name_='NivXForge migration CI fixture'
    def __init__(self,args):
        super().__init__(args);self.stop_event=win32event.CreateEvent(None,0,0,None)
    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
    def SvcDoRun(self):win32event.WaitForSingleObject(self.stop_event,win32event.INFINITE)
if __name__=='__main__':
    servicemanager.Initialize();servicemanager.PrepareToHostSingle(Fixture);servicemanager.StartServiceCtrlDispatcher()
