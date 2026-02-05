# EZ-Milter - Easy SPAM Mail Filter

It is a rule-based email filter using the "Sendmail Milter API" for Postfix.
You can create email filters with just a little perl code.
You can also use the SPF verification function.

このソフトは、Postfix または Sendmail（動作未確認）で動く、ルールベースのSPAMフィルターです。
簡単な Perl のコードを書くだけで、自分思う通りの SPAM フィルターを実装することができます。
またSPF検証機能も使用できます。

# Enviroment

  * Postfix or Sendmail
  * Perl 5.14 or later
  * [Sendmail::PMilter](https://github.com/avar/sendmail-pmilter) in [Sendmail/](./Sendmail/)
  * [libspf2/Mail::SPF_XS](https://github.com/shevek/libspf2/tree/master) (option, require for check SPF)

# 動作環境

 * Postfix または Sendmail
 * Perl 5.14 以降
 * [Sendmail::PMilter](https://github.com/avar/sendmail-pmilter) in [Sendmail/](./Sendmail/)
 * [libspf2/Mail::SPF_XS](https://github.com/shevek/libspf2/tree/master) (オプション。SPF検証に必要)

# Install for Postfix

Add the following configuration to **master.cf** and **reload Postfix**.
```
smtp      inet  n       -       y       -       -       smtpd
  -o    milter_default_action=accept
  -o    smtpd_milters=inet:127.0.0.1:10025
```
```
service postfix reload
```

Download ez-milter as the added user. You can also use git.
```
wget https://github.com/nabe-abk/ez-milter/archive/refs/heads/main.zip
unzip main.zip
mv ez-milter-main ez-milter
```

Initialize the files.
```
cd ez-milter
cp ez-milter.user-filter.pm.sample ez-milter.user-filter.pm
cp milter_start.sh.sample milter_start.sh
chmod +x milter_start.sh
```

Load the test file to check if it works correctly.
```
./ez-milter.pl test/spam00.eml
```

Set ez-milter.pl to start automatically. Here is an example of how to set it up in crontab.
```
# m h  dom mon dow   command
@reboot              ~/ez-milter/milter_start.sh >/dev/null
```

## Install Mail::SPF_XS

For Debian/Ubuntu, enter the following command as root:
```
apt-get install libmail-spf-xs-perl
```

## Coexistence with OpenDKIM verification

Instead of configuring smtpd_milters directly in main.cf, configure it via variables.
```
milter_default_action = accept
milter_protocol   = 6
_smtpd_milters    = local:opendkim/opendkim.sock
smtpd_milters     = $_smtpd_milters
non_smtpd_milters = $smtpd_milters
```

Then, modify the smtpd_milters line in master.cf as follows:
```
   -o smtpd_milters=inet:127.0.0.1:10025,$_smtpd_milters
```


# インストール方法（Postfix）

**mastar.cf**に以下の設定を追加し、**Postfixをリロード**します。
```
smtp      inet  n       -       y       -       -       smtpd
  -o    milter_default_action=accept
  -o    smtpd_milters=inet:127.0.0.1:10025
```
```
service postfix reload
```

EZ-Milter起動用のユーザーを追加します（既存ユーザーでも構いません）。
```
adduser milter
su milter
```

追加ユーザーにて ez-milter をダウンロードします。git を使用しても構いません。
```
wget https://github.com/nabe-abk/ez-milter/archive/refs/heads/main.zip
unzip main.zip
mv ez-milter-main ez-milter
```

ファイルを初期設定します。
```
cd ez-milter
cp ez-milter.user-filter.pm.sample ez-milter.user-filter.pm
cp milter_start.sh.sample milter_start.sh
chmod +x milter_start.sh
```

テストファイルを読み込ませ、正しく動くことを確認します。
```
./ez-milter.pl test/spam00.eml
```

ez-milter.pl を自動起動するように設定します。例として crontab の設定方法を示します。
```
# m h  dom mon dow   command
@reboot              ~/ez-milter/milter_start.sh >/dev/null
```

## Mail::SPF_XS のインストール

Debian/Ubuntuの場合、以下のコマンドをrootで入力します。
```
apt-get install libmail-spf-xs-perl
```

## OpenDKIMの署名検証と共存させる

main.cf で smtpd_milters を直接設定せずに、変数を介して設定します。
```
milter_default_action = accept
milter_protocol   = 6
_smtpd_milters    = local:opendkim/opendkim.sock
smtpd_milters     = $_smtpd_milters
non_smtpd_milters = $smtpd_milters
```

その上で、master.cf の smtpd_milters行を以下のようにします。
```
   -o smtpd_milters=inet:127.0.0.1:10025,$_smtpd_milters
```

# Set filter rules

- The filter rules are written in ez-milter.user-filter.pm.
- If you want to change the filter rules, edit this file.
- If you modify this file while ez-milter.pl is running, it will be automatically reloaded.
	- ez-milter.pl is not automatically reloaded in any case.

In the sample, filtering is performed only on emails addressed to specific users.
If you use it as is, list the destination email addresses you want to use in **%USER**.

# フィルタールールの設定

- ez-milter.user-filter.pm にフィルタールールが書かれています。
- フィルタールールを変更する場合は、このファイルを編集します。
- ez-milter.pl 実行中にこのファイルを書き換えた場合、このファイルは自動的にリロードされます。
	- ez-milter.pl はいかなる場合も自動リロードされません。

サンプルでは、特定のユーザー宛のメールのみフィルター処理を実行するようになっています。
そのまま使用する場合、**%USER** に使用したい宛先メールアドレスを列挙してください。
