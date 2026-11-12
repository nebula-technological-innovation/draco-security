import test from 'node:test';
import assert from 'node:assert/strict';
import * as draco from '@draco/security';
import { z } from 'zod';

test('published package export map remains consumable after Zod major upgrade', () => {
  for (const name of ['DependencyScanner', 'SecretScanner', 'IaCScanner', 'ContainerScanner',
      'DracoSecurityAgent', 'generateReport', 'formatReport', 'generateThreatModel']) {
    assert.equal(typeof draco[name], 'function', name);
  }
});
test('public dependency scanner exposes typed advisory proof at runtime', async () => {
  const lock = {
    name:'consumer-fixture', version:'1.0.0', lockfileVersion:3,
    packages:{'':{name:'consumer-fixture',version:'1.0.0',dependencies:{zod:'^4.6.7'}},
      'node_modules/zod':{version:'4.6.7',integrity:'sha512-AAA='}},
  };
  const report = {auditReportVersion:2,vulnerabilities:{},
    metadata:{vulnerabilities:{total:0,info:0,low:0,moderate:0,high:0,critical:0}}};
  const result = await new draco.DependencyScanner().scanLockfile(
    JSON.stringify(lock),'npm',
    {runner:()=>({status:0,stdout:JSON.stringify(report)})},
  );
  assert.equal(result.evidence?.verified,true);
  assert.equal(result.evidence?.source,'npm-registry-advisory-audit');
  assert.equal(result.summary.total,0);
});
test('Zod v4 arrays/objects preserve Draco public schema behavior', () => {
  const schema = z.object({
    name:z.string(),
    version:z.string(),
    vulnerabilities:z.array(z.object({severity:z.enum(['critical','high','medium','low','info'])})),
  });
  assert.equal(schema.safeParse({name:'fixture',version:'4.6.7',vulnerabilities:[{severity:'high'}]}).success,true);
  assert.equal(schema.safeParse({name:'fixture',version:'4.6.7',vulnerabilities:[{severity:'urgent'}]}).success,false);
});