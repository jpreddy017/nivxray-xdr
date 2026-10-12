import importlib.util
from pathlib import Path
import unittest

path=Path(__file__).resolve().parents[1]/'product_tasks.py'
spec=importlib.util.spec_from_file_location('products',path)
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)


class ProductBoundaryTests(unittest.TestCase):
    def test_outputs_cannot_overwrite_each_other_or_production_scripts(self):
        x,xc,xe=p.command('xdr','build');e,ec,ee=p.command('edr','build');w,wc,we=p.command('workspace','build')
        self.assertEqual(xc,ec)
        self.assertNotEqual(x[x.index('--outDir')+1],e[e.index('--outDir')+1])
        self.assertEqual(xe['REACT_APP_PRODUCT_SCOPE'],'xdr');self.assertEqual(ee['REACT_APP_PRODUCT_SCOPE'],'edr')
        self.assertTrue(we['BUILD_PATH'].endswith('/workspace'))
        for env in [xe,ee,we]:self.assertEqual(env['REACT_APP_BACKEND_URL'],'http://127.0.0.1:9')
        for args in [x,e,w]:self.assertNotIn('vercel-build',args)
    def test_no_company_placeholder_or_workspace_substitution(self):
        with self.assertRaises(ValueError):p.command('company','build')
    def test_existing_sources_remain_mapped(self):p.check()
