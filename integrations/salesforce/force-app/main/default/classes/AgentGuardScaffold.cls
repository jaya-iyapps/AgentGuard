/** Development placeholder only. No authorization, callouts, queries, or DML. */
public with sharing class AgentGuardScaffold {
    public class Input {
        @InvocableVariable(required=true)
        public String requestId;
    }

    public class Output {
        @InvocableVariable
        public String decision;
        @InvocableVariable
        public String reasonCode;
        @InvocableVariable
        public String explanation;
    }

    @InvocableMethod(label='AgentGuard Scaffold (Always Denies)'
                     description='Not implemented. Does not authorize or execute any action.')
    public static List<Output> evaluate(List<Input> inputs) {
        List<Output> outputs = new List<Output>();
        for (Input entry : inputs) {
            Output result = new Output();
            result.decision = 'DENY';
            result.reasonCode = 'NOT_IMPLEMENTED';
            result.explanation = 'AgentGuard integration is not implemented.';
            outputs.add(result);
        }
        return outputs;
    }
}
