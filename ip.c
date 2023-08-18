#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ip.h"

struct ip_hdr
{
    uint8_t vhl;
    uint8_t tos;
    uint16_t total;
    uint16_t id;
    uint16_t offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t sum;
    ip_addr_t src;
    ip_addr_t dst;
    uint8_t options[];
};

struct ip_protocol
{
    struct ip_protocol *next;
    uint8_t type;
    void (*handler)(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface);
};

const ip_addr_t IP_ADDR_ANY = 0x00000000;       /* 0.0.0.0 */
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff; /* 255.255.255.255 */

/* NOTE: if you want to add/delete the entries after net_run(), you need to protect these lists with a mutex. */
static struct ip_iface *ifaces;
static struct ip_protocol *protocols;

int ip_addr_pton(const char *p, ip_addr_t *n)
{
    char *sp, *ep;
    int idx;
    long ret;

    sp = (char *)p;
    for (idx = 0; idx < 4; idx++)
    {
        ret = strtol(sp, &ep, 10);
        if (ret < 0 || ret > 255)
        {
            return -1;
        }
        if (ep == sp)
        {
            return -1;
        }
        if ((idx == 3 && *ep != '\0') || (idx != 3 && *ep != '.'))
        {
            return -1;
        }
        ((uint8_t *)n)[idx] = ret;
        sp = ep + 1;
    }
    return 0;
}

char *ip_addr_ntop(ip_addr_t n, char *p, size_t size)
{
    uint8_t *u8;

    u8 = (uint8_t *)&n;
    snprintf(p, size, "%d.%d.%d.%d", u8[0], u8[1], u8[2], u8[3]);
    return p;
}

static void ip_dump(const uint8_t *data, size_t len)
{
    struct ip_hdr *hdr;
    uint8_t v, hl, hlen;
    uint16_t total, offset;
    char addr[IP_ADDR_STR_LEN];

    flockfile(stderr);
    hdr = (struct ip_hdr *)data;
    v = (hdr->vhl & 0xf0) >> 4;
    hl = hdr->vhl & 0x0f;
    hlen = hl << 2;
    fprintf(stderr, "        vhl: 0x%02x [v: %u, hl: %u (%u)]\n", hdr->vhl, v, hl, hlen);
    fprintf(stderr, "        tos: 0x%02x\n", hdr->tos);
    total = ntoh16(hdr->total);
    fprintf(stderr, "      total: %u (payload: %u)\n", total, total - hlen);
    fprintf(stderr, "         id: %u\n", ntoh16(hdr->id));
    offset = ntoh16(hdr->offset);
    fprintf(stderr, "     offset: 0x%04x [flags=%x, offset=%u]\n", offset, (offset & 0xe000) >> 13, offset & 0x1fff);
    fprintf(stderr, "        ttl: %u\n", hdr->ttl);
    fprintf(stderr, "   protocol: %u\n", hdr->protocol);
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
    fprintf(stderr, "        src: %s\n", ip_addr_ntop(hdr->src, addr, sizeof(addr)));
    fprintf(stderr, "        dst: %s\n", ip_addr_ntop(hdr->dst, addr, sizeof(addr)));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

struct ip_iface *ip_iface_alloc(const char *unicast, const char *netmask)
{
    struct ip_iface *iface;

    iface = memory_alloc(sizeof(*iface));
    if (!iface)
    {
        errorf("memory_alloc() failure");
        return NULL;
    }
    NET_IFACE(iface)->family = NET_IFACE_FAMILY_IP;

    /*
    Exercise 7-3: IPインタフェースにアドレス情報を設定
    (1) iface->unicast : 引数 unicast を文字列からバイナリ値へ変換して設定する
    　・変換に失敗した場合はエラーを返す（不要になった iface のメモリ解放をわすれずに）
    (2) iface->netmask : 引数 netmask を文字列からバイナリ値へ変換して設定する
    　・変換に失敗した場合はエラーを返す（不要になった iface のメモリ解放をわすれずに）
    (3) iface->broadcast : iface->unicast と iface->netmask の値から算出して設定する
    */
    //(1) iface->unicast : 引数 unicast を文字列からバイナリ値へ変換して設定する
    if (ip_addr_pton(unicast, &(iface->unicast)) == -1)
    {

        memory_free(iface);
        errorf("ip_addr_pton failure");
        return NULL;
    }

    //(2) iface->netmask : 引数 netmask を文字列からバイナリ値へ変換して設定する
    if (ip_addr_pton(netmask, &(iface->netmask)) == -1)
    {
        memory_free(iface);
        errorf("ip_addr_pton failure");
        return NULL;
    }
    //(3) iface->broadcast : iface->unicast と iface->netmask の値から算出して設定する
    iface->broadcast = (iface->unicast & iface->netmask) | ~(iface->netmask);

    debugf("finish ip_iface_alloc");
    return iface;
}

/* NOTE: must not be call after net_run() */
int ip_iface_register(struct net_device *dev, struct ip_iface *iface)
{
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    char addr3[IP_ADDR_STR_LEN];

    /*
    Exercise 7-4: IPインタフェースの登録
    (1) デバイスにIPインタフェース（iface）を登録する
    　・エラーが返されたらこの関数もエラーを返す
    (2) IPインタフェースのリスト（ifaces）の先頭に iface を挿入する
    */
    if (net_device_add_iface(dev, &(iface->iface)) == -1)
    {
        debugf("net_device_add_iface failuer");
        return -1;
    }
    iface->next = ifaces;
    ifaces = iface;

    infof("registered: dev=%s, unicast=%s, netmask=%s, broadcast=%s", dev->name,
          ip_addr_ntop(iface->unicast, addr1, sizeof(addr1)),
          ip_addr_ntop(iface->netmask, addr2, sizeof(addr2)),
          ip_addr_ntop(iface->broadcast, addr3, sizeof(addr3)));
    return 0;
}

struct ip_iface *ip_iface_select(ip_addr_t addr)
{
    /*
    Exercise 7-5: IPインタフェースの検索
    ・インタフェースリスト（ifaces）を巡回
    　・引数 addr で指定されたIPアドレスを持つインタフェースを返す
    ・合致するインタフェースを発見できなかったら NULL を返す
    */
    struct ip_iface *entry;

    for (entry = ifaces; entry; entry = entry->next)
    {
        if (entry->unicast == addr)
        {
            return entry;
        }
    }
    return NULL;
}

/* NOTE: must not be call after net_run() */
int ip_protocol_register(uint8_t type, void (*handler)(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface))
{
    struct ip_protocol *entry;
    /*
    Exercise 9-1: 重複登録の確認
    ・プロトコルリスト（protocols）を巡回
    　・指定された type のエントリが既に存在する場合はエラーを返す
    */

    for (entry = protocols; entry; entry = entry->next)
    {
        if (type == entry->type)
        {
            errorf("already registered, type=0x%04x", type);
            return -1;
        }
    }

    /*
    Exercise 9-2: プロトコルの登録
    (1) 新しいプロトコルのエントリ用にメモリを確保
    　・メモリ確保に失敗したらエラーを返す
    (2) 新しいプロトコルのエントリに値を設定
    (3) プロトコルリスト（protocols）の先頭に挿入
    */
    entry = memory_alloc(sizeof(*entry));
    if (!entry)
    {
        errorf("memory_alloc() failure");
        return -1;
    }
    entry->type = type;
    entry->handler = handler;
    entry->next = protocols;
    protocols = entry;

    infof("registered, type=%u", entry->type);
    return 0;
}

static void ip_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct ip_hdr *hdr;
    uint8_t v;
    uint16_t hlen, total, offset;
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];

    if (len < IP_HDR_SIZE_MIN)
    {
        errorf("too short");
        return;
    }
    hdr = (struct ip_hdr *)data;
    /*
    Exercise 6-1: IPデータグラムの検証
    (1) バージョン
        IP_VERSION_IPV4 と一致しない場合はエラーメッセージを出力して中断
    (2) ヘッダ長
        入力データの長さ（len）がヘッダ長より小さい場合はエラーメッセージを出力して中断
    (3) トータル長
        入力データの長さ（len）がトータル長より小さい場合はエラーメッセージを出力して中断
    (4) チェックサム
        cksum16() での検証に失敗した場合はエラーメッセージを出力して中断
    */

    //    (1) バージョン
    //        IP_VERSION_IPV4 と一致しない場合はエラーメッセージを出力して中断

    v = (hdr->vhl & 0xf0) >> 4;
    if (v != IP_VERSION_IPV4)
    {
        errorf("version error");
        return;
    }
    //    (2) ヘッダ長
    //        入力データの長さ（len）がヘッダ長より小さい場合はエラーメッセージを出力して中断
    hlen = (hdr->vhl & 0x0f) << 2;
    if (len < hlen)
    {
        errorf("input len is shorter than header len error");
        return;
    }

    //    (3) トータル長
    //        入力データの長さ（len）がトータル長より小さい場合はエラーメッセージを出力して中断
    total = ntoh16(hdr->total);
    if (len < total)
    {
        errorf("input len is shorter than total len error");
        return;
    }

    //    (4) チェックサム
    //        cksum16() での検証に失敗した場合はエラーメッセージを出力して中断
    if (cksum16((uint16_t *)data, len, 0) != 0)
    {
        errorf("invalid checksum error");
        return;
    }

    offset = ntoh16(hdr->offset);
    if (offset & 0x2000 || offset & 0x1fff)
    {
        errorf("fragments does not support");
        return;
    }

    /*
    Exercise 7-6: IPデータグラムのフィルタリング
    (1) デバイスに紐づくIPインタフェースを取得
    　・IPインタフェースを取得できなかったら中断する
    (2) 宛先IPアドレスの検証
    　・以下のいずれにも一致しない場合は「他ホスト宛」と判断して中断する（エラーメッセージは出力しない）
    　　a. インタフェースのユニキャストIPアドレス
    　　b. ブロードキャストIPアドレス（255.255.255.255）
    　　c. インタフェースが属するサブネットのブロードキャストIPアドレス（xxx.xxx.xxx.255 など）
    */
    for (iface = ifaces; iface; iface = iface->next)
    {
        if (NET_IFACE(iface)->dev == dev)
        {
            break;
        }
    }
    if (!iface)
    {
        errorf("No iface found");
        return;
    }
    if (hdr->dst != iface->unicast &&
        hdr->dst != IP_ADDR_BROADCAST &&
        hdr->dst != iface->broadcast)
    {
        errorf("dst is not for me");
        return;
    }

    debugf("dev=%s, iface=%s, protocol=%u, total=%u",
           dev->name,
           ip_addr_ntop(iface->unicast, addr, sizeof(addr)),
           hdr->protocol,
           total);
    ip_dump(data, total);

    /*
    Exercise 9-3: プロトコルの検索
    ・プロトコルリスト（protocols）を巡回
    　・IPヘッダのプロトコル番号と一致するプロトコルの入力関数を呼び出す（入力関数にはIPデータグラムのペイロードを渡す）
    　・入力関数から戻ったら return する
    ・合致するプロトコルが見つからない場合は何もしない
    */
    struct ip_protocol *protocol;
    for (protocol = protocols; protocol; protocol = protocol->next)
    {
        if (hdr->protocol == protocol->type)
        {
            protocol->handler(data, len, hdr->src, hdr->dst, iface);
            return;
        }
    }
    /* unsupported protocol */
    errorf("unsupported protocol");
}

static int ip_output_device(struct ip_iface *iface, const uint8_t *data, size_t len, ip_addr_t dst)
{
    uint8_t hwaddr[NET_DEVICE_ADDR_LEN] = {};

    if (NET_IFACE(iface)->dev->flags & NET_DEVICE_FLAG_NEED_ARP)
    {
        if (dst == iface->broadcast || dst == IP_ADDR_BROADCAST)
        {
            memcpy(hwaddr, NET_IFACE(iface)->dev->broadcast, NET_IFACE(iface)->dev->alen);
        }
        else
        {
            errorf("arp does not implement");
            return -1;
        }
    }
    /*
    Exercise 8-4: デバイスから送信
    ・net_device_output() を呼び出してインタフェースに紐づくデバイスからIPデータグラムを送信
    ・net_device_output() の戻り値をこの関数の戻り値として返す
    */
    return net_device_output(NET_IFACE(iface)->dev, NET_PROTOCOL_TYPE_IP, data, len, dst);
}

static ssize_t ip_output_core(struct ip_iface *iface,
                              uint8_t protocol,
                              const uint8_t *data,
                              size_t len,
                              ip_addr_t src,
                              ip_addr_t dst,
                              uint16_t id,
                              uint16_t offset)
{
    uint8_t buf[IP_TOTAL_SIZE_MAX];
    struct ip_hdr *hdr;
    uint16_t hlen, total;
    char addr[IP_ADDR_STR_LEN];

    hdr = (struct ip_hdr *)buf;

    /*
    Exercise 8-3: IPデータグラムの生成
    (1) IPヘッダの各フィールドに値を設定
    　　・IPヘッダの長さは IP_HDR_SIZE_MIN 固定とする（オプションなし）
    　　・TOS = 0, TTL = 255 とする
    　　・チェックサムの計算結果はバイトオーダーを変換せずにそのまま設定する（ネットワークバイトオーダーのバイト列のチェックサム計算結果はネットワークバイトオーダーで得られる）
    　　　・チェックサム計算の際、あらかじめチェックサムフィールドに 0 を設定するのを忘れずに
    (2) IPヘッダの直後にデータを配置（コピー）する
    */
    hlen = IP_HDR_SIZE_MIN >> 2;
    total = IP_HDR_SIZE_MIN + len;

    hdr->vhl = (IP_VERSION_IPV4 << 4) | (hlen);
    hdr->tos = 0;
    hdr->ttl = 255;
    hdr->total = hton16(total);
    hdr->id = hton16(id);
    hdr->offset = hton16(offset);
    hdr->protocol = protocol;
    hdr->sum = 0;
    hdr->sum = cksum16(hdr, IP_HDR_SIZE_MIN, 0);
    hdr->src = src;
    hdr->dst = dst;

    memcpy(hdr + IP_HDR_SIZE_MIN, data, len);

    debugf("dev=%s, dst=%s, protocol=%u, len=%u",
           NET_IFACE(iface)->dev->name, ip_addr_ntop(dst, addr, sizeof(addr)), protocol, total);
    ip_dump(buf, total);
    return ip_output_device(iface, buf, total, dst);
}

static uint16_t ip_generate_id(void)
{
    static mutex_t mutex = MUTEX_INITIALIZER;
    static uint16_t id = 128;
    uint16_t ret;

    mutex_lock(&mutex);
    ret = id++;
    mutex_unlock(&mutex);
    return ret;
}

ssize_t ip_output(uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst)
{
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];
    uint16_t id;

    if (src == IP_ADDR_ANY)
    {
        errorf("ip routing does not implement");
        return -1;
    }
    else
    { /* NOTE: I'll rewrite this block later. */

        /*
        Exercise 8-1: IPインタフェースの検索
        ・送信元IPアドレス（src）に対応するIPインタフェースを検索
        　・インタフェースが見つからない場合はエラーを返す
        */
        for (iface = ifaces; iface; iface = iface->next)
        {
            if (iface->unicast == src)
            {
                break;
            }
        }
        if (!iface)
        {
            errorf("No iface found");
            return -1;
        }
        /*
        Exercise 8-2: 宛先へ到達可能か確認
        ・宛先アドレス（dst）が以下の条件に合致しない場合はエラーを返す（到達不能）
        　・インタフェースのネットワークアドレスの範囲に含まれる
        　・ブロードキャストIPアドレス（255.255.255.255）
         */

        if (dst != IP_ADDR_BROADCAST &&
            (iface->unicast & iface->netmask) != (dst & iface->netmask))
        {

            errorf("dst is not reachable addr. %u, %u", iface->unicast & iface->netmask, dst & iface->netmask);
            return -1;
        }
    }
    if (NET_IFACE(iface)->dev->mtu < IP_HDR_SIZE_MIN + len)
    {
        errorf("too long, dev=%s, mtu=%u < %zu",
               NET_IFACE(iface)->dev->name, NET_IFACE(iface)->dev->mtu, IP_HDR_SIZE_MIN + len);
        return -1;
    }
    id = ip_generate_id();
    if (ip_output_core(iface, protocol, data, len, iface->unicast, dst, id, 0) == -1)
    {
        errorf("ip_output_core() failure");
        return -1;
    }
    return len;
}

int ip_init(void)
{
    if (net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input) == -1)
    {
        errorf("net_protocol_register() failure");
        return -1;
    }
    return 0;
}