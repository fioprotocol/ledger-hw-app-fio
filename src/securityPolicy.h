#ifndef H_FIO_APP_SECURITY_POLICY
#define H_FIO_APP_SECURITY_POLICY

#include "bip44.h"
#include "getPublicKey.h"

typedef enum {
	POLICY_DENY = 1,
	POLICY_ALLOW_WITHOUT_PROMPT = 2,
	POLICY_PROMPT_BEFORE_RESPONSE = 3,
	POLICY_PROMPT_WARN_UNUSUAL = 4,
	POLICY_SHOW_BEFORE_RESPONSE = 5, // Show on display but do not ask for explicit confirmation
} security_policy_t;

security_policy_t policyForGetPublicKey(const bip44_path_t* pathSpec, get_key_p1_t show_or_not);

security_policy_t policyForSignTxInit(network_type_t network);
security_policy_t policyForSignTxHeader();
security_policy_t policyForSignTxActionHeader(action_type_t action);
security_policy_t policyForSignTxActionAuthorization();
security_policy_t policyForSignTxActionData(char * validation_actor, char* data_actor);
security_policy_t policyForSignTxWitness(const bip44_path_t* pathSpec);

security_policy_t policyDerivePrivateKey(const bip44_path_t* pathSpec);

static inline void ENSURE_NOT_DENIED(security_policy_t policy)
{
	if (policy == POLICY_DENY) {
		THROW(ERR_REJECTED_BY_POLICY);
	}
}

#endif // H_FIO_APP_SECURITY_POLICY
