#!/usr/bin/env python3

import re
from pathlib import Path

path = Path("/usr/share/perl5/PVE/API2/Nodes.pm")
data = path.read_text()

has_restore_endpoint = "restore_vma" in data
has_reset_endpoint = "reset_conntrack" in data

if has_reset_endpoint:
    print("reset_conntrack endpoint already present; nothing to do.")
    raise SystemExit(0)

data = data.replace(
    "{ name => 'restore-vma' },\n            { name => 'report' },",
    "{ name => 'restore-vma' },\n            { name => 'reset-conntrack' },\n            { name => 'report' },",
    1,
)

if "{ name => 'reset-conntrack' }" not in data:
    data = data.replace(
        "{ name => 'replication' },\n            { name => 'report' },",
        "{ name => 'replication' },\n            { name => 'restore-vma' },\n            { name => 'reset-conntrack' },\n            { name => 'report' },",
        1,
    )

if "{ name => 'reset-conntrack' }" not in data:
    raise SystemExit("Could not insert reset-conntrack entry into node index list.")

report_block = re.search(
    r"__PACKAGE__->register_method\(\{\n\s+name => 'report'.*?\n\}\);\n",
    data,
    flags=re.S,
)
if not report_block:
    raise SystemExit("Could not locate the report endpoint block in Nodes.pm")

if not has_restore_endpoint:
    insert_restore = """
__PACKAGE__->register_method({
    name => 'restore_vma',
    path => 'restore-vma',
    method => 'POST',
    permissions => {
        check => ['perm', '/nodes/{node}', ['Sys.Modify']],
    },
    protected => 1,
    proxyto => 'node',
    description => "Restore a VM disk from a VMA backup using a host script.",
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            vmid => get_standard_option('pve-vmid'),
            backup => {
                description => 'Path to the VMA archive to restore from.',
                type => 'string',
                optional => 1,
            },
        },
    },
    returns => {
        type => 'string',
    },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();
        my $authuser = $rpcenv->get_user();

        my $node = $param->{node};
        $node = PVE::INotify::nodename() if $node eq 'localhost';
        PVE::Cluster::check_node_exists($node);

        my $vmid = $param->{vmid};
        my $backup = $param->{backup};
        my $script = '/var/lib/svz/snippets/restore-vm-disk-from-vma.sh';

        my $code = sub {
            die "script '$script' not found\\n" if !-f $script;
            die "script '$script' not executable\\n" if !-x $script;

            my @cmd = ($script, $vmid);
            push @cmd, $backup if defined($backup) && length($backup);

            PVE::Tools::run_command(\\@cmd, errmsg => 'restore VM from VMA failed');
        };

        return $rpcenv->fork_worker('restorevmvma', $vmid, $authuser, $code);
    },
});
"""

    data = data[:report_block.end()] + insert_restore + data[report_block.end():]

restore_block = re.search(
    r"__PACKAGE__->register_method\(\{\n\s+name => 'restore_vma'.*?\n\}\);\n",
    data,
    flags=re.S,
)
if not restore_block:
    raise SystemExit("Could not locate the restore_vma endpoint block in Nodes.pm")

insert_reset = """
__PACKAGE__->register_method({
    name => 'reset_conntrack',
    path => 'reset-conntrack',
    method => 'POST',
    permissions => {
        check => ['perm', '/nodes/{node}', ['Sys.Modify']],
    },
    protected => 1,
    proxyto => 'node',
    description => "Clear conntrack entries for a VM's public IP addresses using a host script.",
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            vmid => get_standard_option('pve-vmid'),
        },
    },
    returns => {
        type => 'string',
    },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();
        my $authuser = $rpcenv->get_user();

        my $node = $param->{node};
        $node = PVE::INotify::nodename() if $node eq 'localhost';
        PVE::Cluster::check_node_exists($node);

        my $vmid = $param->{vmid};
        my $script = '/var/lib/svz/snippets/reset-vm-conntrack.py';

        my $code = sub {
            die "script '$script' not found\\n" if !-f $script;
            die "script '$script' not executable\\n" if !-x $script;

            my @cmd = ($script, $vmid);

            PVE::Tools::run_command(\\@cmd, errmsg => 'reset VM conntrack failed');
        };

        return $rpcenv->fork_worker('resetvmconntrack', $vmid, $authuser, $code);
    },
});
"""

data = data[:restore_block.end()] + insert_reset + data[restore_block.end():]
path.write_text(data)
print("restore_vma and reset_conntrack endpoints added successfully.")
