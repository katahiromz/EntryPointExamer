(UTF-8, Japanese)

////////////////////////////////////////////////
epx --- EntryPointExamer by 片山博文MZ
////////////////////////////////////////////////

このソフトウェアは、指定されたプログラムファイルが、特定のOSで
起動するかどうかをエントリーポイントを調べることで判定する、静的
解析ツールです。

使い方：

(1)
    epx --os-info win98se.info myfile.exe

    myfile.exeがWindows 98 SEで起動するかどうかを判定します。

(2)
    epx --os-info mywinos.info --generate

    現在のOSの情報をファイル「mywinos.info」に出力します。

---
片山博文MZ
katayama.hirofumi.mz@gmail.com
