@IsTest
private class AgentGuardScaffoldTest {
    @IsTest
    static void deniesEveryInput() {
        AgentGuardScaffold.Input request = new AgentGuardScaffold.Input();
        request.requestId = 'synthetic-request';
        Test.startTest();
        List<AgentGuardScaffold.Output> results = AgentGuardScaffold.evaluate(
            new List<AgentGuardScaffold.Input>{request}
        );
        Test.stopTest();
        System.assertEquals(1, results.size());
        System.assertEquals('DENY', results[0].decision);
        System.assertEquals('NOT_IMPLEMENTED', results[0].reasonCode);
        System.assertEquals(0, Limits.getDmlStatements());
        System.assertEquals(0, Limits.getCallouts());
    }
}
