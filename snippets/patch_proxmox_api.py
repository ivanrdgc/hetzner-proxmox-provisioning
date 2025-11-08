#!/usr/bin/env python3

import re
from pathlib import Path

path = Path("/usr/share/perl5/PVE/API2/Nodes.pm")
data = path.read_text()

if "restore_vma" in data:
    print("restore_vma endpoint already present; nothing to do.")
    raise SystemExit(0)

data = data.replace(
    "{ name => 'replication' },\n            { name => 'report' },",
    "{ name => 'replication' },\n            { name => 'restore-vma' },\n            { name => 'report' },",
    1,
)

report_block = re.search(
    r"__PACKAGE__->register_method\(\{\n\s+name => 'report'.*?\n\}\);\n",
    data,
    flags=re.S,
)
if not report_block:
    raise SystemExit("Could not locate the report endpoint block in Nodes.pm")

insert = """
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

data = data[:report_block.end()] + insert + data[report_block.end():]
path.write_text(data)
print("restore_vma endpoint added successfully.")
