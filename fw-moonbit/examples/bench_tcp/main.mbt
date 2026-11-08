// ============================================================
// bench_tcp —— TcpFrameParser（逐字节状态机）可复跑基准
//
// 与 .bench/bench-feed.mjs（Node TcpStreamParser）/.bench/bench-c.c（fw_sp_feed）
// 同口径，三个场景：
//   A 1MB 单帧（PLB=3）按 1400B 分片喂入（模拟大 payload 慢速到达）
//   B 750 个 1400B 帧粘包，按 1MB 块喂入（模拟批量粘包）
//   C 1MB 单帧一次性喂入（基线）
//
// 运行：moon run examples/bench_tcp --target js
// 输出：场景名 delivered/bytes/time/throughput（与 Node/C 基准字段一致）
// ============================================================

/// 高精度单调时钟（performance.now，毫秒）
extern "js" fn bench_now(_x : Int) -> Double = "(_) => performance.now()"

/// 运行单个场景：按 chunk 字节分片喂入，统计完整交付帧数与耗时/吞吐
fn run_bench(name : String, data : Bytes, chunk : Int) -> Unit {
  let p = @frame.TcpFrameParser::new(0, 5000L)
  let mut delivered = 0
  let t0 = bench_now(0)
  let mut i = 0
  while i < data.length() {
    let end = if i + chunk < data.length() { i + chunk } else { data.length() }
    for e in p.feed(@codec.sub_bytes(data, i, end), 0L) {
      match e {
        @frame.TcpFrame(_) => delivered = delivered + 1
        _ => ()
      }
    }
    i = i + chunk
  }
  let ms = bench_now(0) - t0
  let mb = data.length().to_double() / 1048576.0
  let mbs = if ms > 0.0 { mb / (ms / 1000.0) } else { 0.0 }
  println(
    name +
    ": delivered=" + delivered.to_string() +
    " bytes=" + data.length().to_string() +
    " time=" + ms.to_string() + "ms" +
    " throughput=" + mbs.to_string() + "MB/s",
  )
}

fn main raise {
  // A/C：1MB 单帧（PLB=3）
  let big_pl = @codec.bytes_of_array(Array::make(1048576, b'\x33'))
  let big = @frame.encode_frame(@frame.data_spec(@frame.Non, 0x01, 1, 1, 1, 1), big_pl, None)

  // B：750 × 1400B 帧（8B 头 + 2B Length + 1390B payload）粘包
  let pl = @codec.bytes_of_array(Array::make(1390, b'\x5A'))
  let one = @frame.encode_frame(@frame.data_spec(@frame.Non, 0x02, 1, 1, 1, 1), pl, None)
  let all : Array[Byte] = []
  for _ in 0..<750 {
    for b in one {
      all.push(b)
    }
  }
  let batch = @codec.bytes_of_array(all)

  run_bench("B 750帧粘包/1MB块", batch, 1048576)
  run_bench("A 1MB单帧/1400B分片", big, 1400)
  run_bench("C 1MB单帧/一次喂入", big, big.length())
}
