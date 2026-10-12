# eudi-dev 2.7.2 wallet

A state directory that eudi-dev 2.7.2 wrote, kept as it was. The upgrade tests in `upgrade_272_test.go` open a copy of it. The keys are throwaway test keys.

It was made with a v2.7.2 build and `EUDI_DEV_HOME` set to an empty directory:

```sh
W="--wallet --remote local --storage file --exp 87600h"
eudi issue sdjwt $W --pid
eudi issue sdjwt $W --trust-profile local --vct urn:test:membership:1 \
  --claims '{"member_id":"M-1001","given_name":"Erika","issuing_country":"NL"}' \
  --save-template membership
eudi issue mdoc $W --trust-profile local --doc-type org.test.membership.1 \
  --namespace org.test.membership.1 \
  --claims '{"member_id":"M-1001","given_name":"Erika","issuing_country":"NL"}'
```

The write lock file was removed. Do not regenerate it with a newer version.
