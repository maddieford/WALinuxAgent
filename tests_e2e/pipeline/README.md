# Existing VM CSE test

Run `tests_e2e/pipeline/pipeline.yml` with all three parameters:

| Parameter | Value |
| --- | --- |
| `subId` | Subscription ID of the existing VM |
| `rgName` | Resource group containing the VM |
| `VMname` | Name of the Linux VM |

Supplying any of these parameters selects only the existing-VM CSE job. All
three are required. Leave all three as `-` to use the normal e2e runner.
The other e2e parameters (including `test_suites`, `image`, and
`keep_environment`) apply only to the normal runner, not the CSE job.

The pipeline's `connection_info` service connection must authenticate to the
VM's cloud and have permission to read the VM and its extensions and write VM
extensions in the target subscription. The VM must be running with a working
Linux agent and connectivity required to download and execute CSE. The CSE
operation needs no SSH, public IP address, container, Key Vault secrets, or
test-agent installation.

The test installs `Microsoft.Azure.Extensions.CustomScript` version `2.1`,
runs a harmless echo command containing a unique marker, and verifies successful
provisioning and that marker in the extension's instance view. If CSE already
exists, the test uses its current resource name and forces an update of its
settings. **This replaces the existing CSE command/settings**, rather than
rerunning the old command. An unrelated extension named `CustomScript` is not
overwritten.

**The extension is left installed**, including after a verification failure.
The test does not replace/configure the VM agent, delete other extensions, or
delete the VM or resource group. Reruns force CSE to execute a new marker command.
Results are published to the pipeline's Tests tab and as the `cse-test-result`
JUnit artifact; Azure CLI errors are recorded in the job log.

## SSH log collection

`collect_logs` applies to this job: `failed` (default) collects after CSE fails,
`always` also collects on success, and `no` disables SSH entirely. Configure
`vm_user` (default `waagent`) for the existing VM. The pipeline uses the existing
`id_rsa` secure file; its public key must already be authorized on the VM, and
the user must have passwordless sudo access for `tar`.

Set `ssh_host` to a hostname/IP reachable from `waagent-pool`, or leave it as `-`
to discover the VM's public IP (falling back to its private IP). The runner must
have network access to SSH port 22; this test does not modify NSGs, SSH keys, or
the VM's configuration. SSH accepts a previously unknown host key but rejects a
changed key. No guest-side test tools are installed. Logs from `/var/log`,
`/var/lib/waagent`, and `/etc/waagent.conf`, where present, are streamed into
`vm-logs.tgz` in the artifact. Treat the archive as potentially sensitive.
Log collection failures are explicitly reported as a separate failed test and
do not replace the CSE test result.

The same test can be run locally after `az login`:

```bash
python3 tests_e2e/tests/cse/add_cse.py \
  --subscription "<subscription-id>" \
  --resource-group "<resource-group>" \
  --vm "<vm-name>" \
  --junit-file /tmp/cse.junit.xml
```

For local SSH collection, also pass `--collect-logs always --ssh-user "<user>"`
and `--identity-file "<private-key-path>"`, with `--ssh-host "<host>"` if needed.
