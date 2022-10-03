---
title: SEKAICTF misc writeup
author: kanon
date: 2022-10-04 00:00:00 +0800
categories: [ctf,writeup]
tags: [ctf,writeup]
math: true
mermaid: true
# image:
#   path: /commons/devices-mockup.png
#   width: 800
#   height: 500
#   alt: Responsive rendering of Chirpy theme on multiple devices.
---

# はじめに
SEKAICTFが10/1-10/3までの計48時間で開催されました。\\
ボカロが好きなのもあって色々期待してましたが、UIしかり、問題しかり想像以上でした。\\
そして[Satoooon](https://twitter.com/satoooon1024)さんと初チーム「Double Lariat」で組んで出ましたが、ものすごく楽しかったし、面白かったです!!\\
更に結果は16位で上々もいいところでした!!\\
\\
さて前置きはこれくらいにして、今回Cryptoのwriteupは要らないかなと思う(難しいのが解けなかったorz)ので解けたmiscだけでいいですか...?\\
どちらかというと問題の凝り方に感激してたもので...

## 問題

ボカロ好きにはたまらない問題セットでした...!!


### Console Port

内容はコンソール版のKeep Talking and Nobody Explodesで、これ作るの大変じゃない???と思いつつ仕様書とにらめっこして解きました。\\
![console port](https://github.com/kanzya/photo/raw/main/SEKAICTF/bakudan.png)
何も変な部分はなかったはずなので、特に気を付けるのは集中力を切らさないことでしたね...\\

flag : *SEKAI{SenkouToTomoniHibikuBakuon!}*

flag見て色々納得した

*サイバーサンダーサイダー　サイバーサンダーサイダー*いいよね～


### Sus

拡張子がsusのファイルを調べると音ゲーの拡張子であることがわかります。しかも、内容は譜面らしくどう読み込ませるのかうなっていたら、[名前的になんかこれじゃん](https://github.com/crash5band/MikuMikuWorld)的なものを見つけ食わせたらビンゴでした。

![sus](https://github.com/kanzya/photo/raw/main/SEKAICTF/sus.png)

flag : *SEKAI{SbtnFmnW2HnYbdDkryunTkrrtims}*

flagも音楽の記号?で凝ってましたね

### Vocaloid Heardle
flagのmp3とそれを作ったであろうpythonファイルが渡されます。\\
とりあえずflagのmp3を聞いてみると3秒ごとに音楽が切り替わってました。\\
次にpythonファイルを覗くとflagのmp3は650個ほどの曲のリストを取ってきてflagの文字から対応する曲をつなげて返す感じでした。\\
リストが多すぎるのでshazamパイセンにお願いすることに...\\
まず、flagをそれぞれ一曲ごとに分割しshazamに曲の判別をしてもらい固有のIDを返却してもらいました。\\
ただ、これでも「ニア」・「自傷無色」は判別してくれなかったので歌詞を頼りに名前を当てIDを調べる。\\
これで準備が整ったのでshazamに全ての曲を食わせてIDの比較を行うとflagが特定できます。

ちなみに、途中バグリ散らかしてたのでリソースにある曲のリストを作ってました。
```
0,Tell Your World (feat. Hatsune Miku) - livetune
1,ロキ - みきとP
2,ROKI (feat. 星乃一歌 & Hatsune Miku) - Leo/need
3,Teo - Omoi
4,Teo (feat. 星乃一歌 & Hatsune Miku) - Leo/need
5,ヒバナ -Reloaded- - DECO*27
6,HIBANA - Reloaded - (feat. 星乃一歌 & Hatsune Miku) - Leo/need
7,Timemachine (feat. Hatsune Miku) - Senroppyaku yonjuu meter P
8,Time Machine (feat. 星乃一歌, 天馬咲希 & Hatsune Miku) - Leo/need
9,Happy Synthesizer (feat. Megurine Luka&GUMI) - EasyPop
10,Happy Synthesizer (feat. 花里みのり, 桐谷遥, 桃井愛莉 & 日野森雫) - MORE MORE JUMP!
11,Viva Happy (feat. Hatsune Miku) - Mitchie M
12,Viva Happy (feat. Hatsune Miku) - Mitchie M
13,Nostalogic (MEIKO-SAN mix) feat.MEIKO - yuukiss
14,Nostalogic (feat. 桐谷遥, 日野森雫 & MEIKO) - MORE MORE JUMP!
15,Drop Pop Candy (feat. Giga) - Reol
16,drop pop candy (feat. 小豆沢こはね, 白石杏, 鏡音リン & 巡音ルカ) - Vivid BAD SQUAD
17,Night Sky Patrol of Tomorrow (feat. 星乃一歌) - Leo/need
18,Charles - Balloon
19,Charles (feat. 東雲絵名 & 暁山瑞希) - Nightcord at 25:00
20,脱法ロック - Neru
21,Law-evading Rock (feat. 天馬司, 神代類 & 鏡音レン) - ワンダーランズ×ショウタイム
22,Inochi ni Kirawarete Iru. - Mafumafu
23,Hated by Life (feat. 宵崎奏 & Hatsune Miku) - Nightcord at 25:00
24,劣等上等 feat. 鏡音リン・レン - Giga
25,劣等上等 feat. 鏡音リン・レン - Giga
```

これ曲名が重なってるところは歌っている人のバージョンが違うみたいでしたね...これ用意したのえぐない????\\
作問者に頭が上がりません...\\

flag :*SAKAI{v0CaloId<3u}*

ごめんなさい、flagの最後が読めなかったです...vocaloid ceu??ですかね...

読める方こっそり教えてください...
