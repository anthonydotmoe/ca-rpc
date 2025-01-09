# Sample Certificate Renewal Server

## Prerequisites

- Install Debian on the server
- Set up the computer identity in AD

## Join the server to the computer identity

1. Install `krb5-user` and `adcli`

    ```
    sudo apt update
    sudo apt install krb5-user adcli
    ```

1. Configure Kerberos to point to the Active Directory domain

    Edit `/etc/krb5.conf`
    ```ini
    [libdefaults]
        default_realm = AD.EXAMPLE.COM
        dns_lookup_realm = true
        dns_lookup_kdc = true
        ticket_lifetime = 10h
        renew_lifetime = 7d
        rdns = false
    
    [realms]
    # Define only if DNS lookups are not working
    # But really, just fix your DNS.
    # AD.EXAMPLE.COM = {
    #     kdc = dc1.ad.example.com
    #     kdc = dc2.ad.example.com
    # }

    [domain_realm]
    # Again, only define if DNS isn't working
    # .ad.example.com = AD.EXAMPLE.COM
    # ad.example.com = AD.EXAMPLE.COM
    ```

    You can test the configuration by attempting to authenticate as a user:

    ```bash
    KRB5_TRACE=/dev/stdout kinit -V aduser@AD.EXAMPLE.COM
    ```

    You'll receive lots of cool output including the DNS lookups and related
    statuses. After you type in your password, you should see
    `Authenticated to Kerberos v5`. You can "log out" by executing `kdestroy`.

1. Join the computer to the domain

    Make sure the server's hostname is set to it's fully qualified name. Use a
    user that has permission to join this computer to the domain. I don't
    specify the `--domain` option since it should pick up on the domain via the
    computer's hostname.

    ```bash
    sudo adcli join -U <Authorized Username>
    ```

    This command will set up the keytab for the machine, and does not configure
    an authentication service. This is fine, since the computer account will be
    doing all the work.

    Now you can test that the join worked:

    ```bash
    sudo adcli testjoin
    ```

1. Set up the key rollover timer

    Also known as the 30-day computer password change service.

    Service file: `/etc/systemd/system/update-keytab.service`

    ```ini
    [Unit]
    Description=Update Kerberos Keytab

    [Service]
    Type=oneshot
    ExecStart=/usr/bin/adcli update --computer-password-lifetime=27
    ```

    Timer file: `/etc/systemd/system/update-keytab.timer`

    ```ini
    [Unit]
    Description=Timer for Kerberos Keytab Update

    [Timer]
    OnCalendar=daily
    Persistent=true

    [Install]
    WantedBy=timers.target
    ```

    `adcli` will be ran daily, and if the computer password is within three days
    of expiring, it changes it.

## Build the program

1. Install prerequsites

    ```bash
    sudo apt install automake bison build-essential cmake flex git libkrb5-dev libtool m4
    ```

1. Build & install `dcerpc`

    ```bash
    git clone "https://github.com/dcerpc/dcerpc"
    cd dcerpc/dcerpc
    libtoolize
    autoreconf -fi
    ./configure --enable-gss_negotiate
    make
    sudo make install
    ```

1. Build `ca-rpc`

    ```bash
    git clone "https://github.com/anthonydotmoe/ca-rpc"
    cd ca-rpc
    mkdir build
    cd build
    cmake ..
    make
    ```

## Create the service scripts

This process could be put together in a script and ran as a cronjob/systemd
timer. You could set go through a list of servers, SSH into them, and renew
their certificates, provided you give this server permission to do that.


```bash
# Retrieve krbtgt for computer account
kinit -kt /etc/krb5.keytab 'HOSTNAME$@AD.EXAMPLE.COM'

# Request the certificate
./ca-rpc -s eca.ad.example.com -c "Enterprise CA" -t "CertificateTemplateName" -r certificate.csr

# ...Profit?
ls certificate.cer

```