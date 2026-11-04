import base64,unittest
import operations,ops_extended
from command_analyzer import analyze_command,_wrapped_powershell,tokenize
class Evidence(unittest.TestCase):
    def test_original_offsets_and_recovery(self):
        payload=base64.b64encode('Write-Output hello'.encode('utf-16le')).decode()
        for space in ('','  ','\t','\n '):
            for prefix in ('powershell -enc ','cmd /c powershell -enc ','%COMSPEC% /b /c start /b /min powershell -enc '):
                with self.subTest(space=space,prefix=prefix):
                    text=space+prefix+payload+'  '
                    r=analyze_command(text)
                    self.assertEqual(r['original_command'],text)
                    self.assertIn('Write-Output hello',str(r['decode_chains']))
                    for span in r['identified_payloads']:
                        if span['offset']>=0:self.assertEqual(text[span['offset']:span['offset']+len(span['span'])],span['span'])
    def test_not_invocations(self):
        for text in ('echo powershell -enc YQBiAGMA','cmd /c echo powershell -enc YQBiAGMA','cmd /c start "powershell -enc YQBiAGMA"'):
            self.assertIsNone(_wrapped_powershell(text))
    def test_windows_paths_preserved(self):
        text=r'C:\Windows\System32\cmd.exe /c type C:\Users\Public\file.txt'
        tokens=tokenize(text)
        self.assertEqual(tokens[0],r'C:\Windows\System32\cmd.exe')
        self.assertEqual(tokens[-1],r'C:\Users\Public\file.txt')
        self.assertEqual(tokenize(r'"C:\Program Files\Tool\tool.exe" "C:\Some Folder\file.txt"')[1],r'C:\Some Folder\file.txt')
    def test_posix_escaping_unchanged(self):
        self.assertEqual(tokenize(r'echo hello\ world'),['echo','hello world'])
        self.assertEqual(tokenize(r"bash -c 'printf C:\\Temp'"),['bash','-c',r'printf C:\\Temp'])
    def test_file_operand(self):
        self.assertEqual(analyze_command('certutil -decode input.b64 output.exe')['decode_chains'],[])
if __name__=='__main__':unittest.main()
