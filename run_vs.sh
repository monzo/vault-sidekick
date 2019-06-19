export VAULT_ADDR=https://secretstore-vault-elb.eu-west-1.i.s101.nonprod-ffs.io:8200
export VAULT_AUTH_METHOD=token
export VAULT_OUTPUT=/Users/gilbertobertin/vault-test
export VAULT_SIDEKICK_RESOURCES_YAML=/Users/gilbertobertin/vault-test/resources.yaml

./vault-sidekick -alsologtostderr
