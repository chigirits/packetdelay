# packetdelay v1.0

条件に合致するパケットに一定時間の遅延をかけて再送信するツールです。
ネットワーク関連機能のデバッグ等に有用です。

## つかいかた

1. `packetdelay-example.ini` をコピーして `packetdelay.ini` にリネームし、後述のとおり [設定の変更](#設定の変更) を行う
2. `packetdelay.exe` を実行
3. 管理者権限を求められるのでOKする
4. コンソールウィンドウが表示されている間、条件に合致するすべてのパケットに一定時間の遅延がかかります
5. Ctrl+Cを押して中断するか、ウィンドウを閉じると元に戻ります

## 設定の変更

`packetdelay.ini` をテキストエディタで開き、目的の動作に合わせて変数の内容を変更してください。

- `network` セクション
  - `filter`: パケットのフィルタリング条件です。書式は [WinDivertのドキュメント](https://reqrypt.org/windivert-doc.html#filter_language) をお読みください。`packetdelay-example.ini` では、外部のUDPポート `50000` への送信パケットを対象とする式が例として設定されています。
  - `delay_time`: 遅延時間（ミリ秒単位）
  - `buffer_size`: バッファサイズ（パケット数）。遅延時間内にこの数を超えるパケットを受信すると、その時点で蓄積されている全パケットがドロップされます。デバッグオプション指定時に表示される `buffer_len` の値（＝そのとき蓄積されているパケット数）を参考に、適切なサイズを決定してください。
  - `priority`: プライオリティ。通常は `0` のままにしておいてください。
- `debug` セクション
  - `debug`: 通常は `0` です。デバッグ情報を表示するときは `1` にしてください。

## おことわり

無保証です。ご自身の責任において使用してください。

Author: chigirits@gmail.com
