package PVE::API2::Custom::Restore;
use strict;
use warnings;
use PVE::Tools qw(run_command);
use PVE::RESTHandler;
use PVE::INotify;
use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'restore_vm_disk',
    path => '',
    method => 'POST',
    protected => 1,
    description => "Restore VM main disk from a VMA backup on this node.",
    parameters => {
        additionalProperties => 0,
        properties => {
            node => { type => 'string', description => 'Node name (must match local node)' },
            vmid => { type => 'integer', description => 'VM ID to restore' },
            backup => {
                type => 'string',
                description => 'Path to VMA backup',
                optional => 1,
            },
        },
    },
    returns => {
        type => 'object',
        properties => {
            stdout => { type => 'string' },
            stderr => { type => 'string' },
            returncode => { type => 'integer' },
        },
    },
    code => sub {
        my ($param) = @_;
        my $local = PVE::INotify::nodename();
        die "Request must target local node ($local)\n"
            if $param->{node} ne $local;
        my $cmd = ["/var/lib/svz/snippets/restore-vm-disk-from-vma.sh",
                   $param->{vmid}, $param->{backup}];
        my ($out,$err) = ('','');
        my $rc = 0;
        eval {
            run_command($cmd, outfunc => sub { $out .= "$_[0]\n" },
                             errfunc => sub { $err .= "$_[0]\n" });
        };
        $rc = 1 if $@;
        return { stdout=>$out, stderr=>$err, returncode=>$rc };
    }});
1;
