# collect-EtcData.ps1 の鍵認証(-KeyFile)検証用 SSH サーバー
#   keyuser : パスフレーズなし鍵(ed25519 / RSA) + NOPASSWD sudo
#   keypp   : パスフレーズ付き鍵(ed25519, パスフレーズ KeyPass#1) + パスワード付き sudo(SudoPass#1)
# パスワード認証は無効(鍵のみ)。鍵はビルド時に /lab/keys へ生成するため、docker cp で取り出して使う。
# ※ 検証専用。鍵・パスワードは固定値のため、外部に公開しないこと(127.0.0.1 にのみ公開する)。
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server openssh-client sudo iproute2 procps \
 && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd /lab/keys
RUN useradd -m -s /bin/bash keyuser && useradd -m -s /bin/bash keypp \
 && echo 'keypp:SudoPass#1' | chpasswd && passwd -l keyuser \
 && usermod -aG sudo keypp \
 && echo 'keyuser ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/keyuser && chmod 440 /etc/sudoers.d/keyuser
RUN ssh-keygen -q -t ed25519 -N '' -C keyuser -f /lab/keys/keyuser_ed25519 \
 && ssh-keygen -q -t rsa -b 3072 -N '' -C keyuser-rsa -f /lab/keys/keyuser_rsa \
 && ssh-keygen -q -t ed25519 -N 'KeyPass#1' -C keypp -f /lab/keys/keypp_ed25519 \
 && for u in keyuser keypp; do install -d -m 700 -o $u -g $u /home/$u/.ssh; done \
 && cat /lab/keys/keyuser_ed25519.pub /lab/keys/keyuser_rsa.pub > /home/keyuser/.ssh/authorized_keys \
 && cat /lab/keys/keypp_ed25519.pub > /home/keypp/.ssh/authorized_keys \
 && chown keyuser:keyuser /home/keyuser/.ssh/authorized_keys && chown keypp:keypp /home/keypp/.ssh/authorized_keys \
 && chmod 600 /home/*/.ssh/authorized_keys
RUN printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nPermitRootLogin no\n' > /etc/ssh/sshd_config.d/10-lab.conf
EXPOSE 22
CMD ["/usr/sbin/sshd","-D","-e"]
