#include "npa/config.hpp"
#include "npa/pcap_capture.hpp"
#include "npa/pcap_writer.hpp"
#include "npa/parser.hpp"
#include "npa/stats.hpp"

#include <boost/asio.hpp>
#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

static uint64_t now_ms() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

int main(int argc, char** argv) {
  using namespace npa;

  Config cfg = parse_args(argc, argv);

  boost::asio::io_context io;
  Stats stats;

  boost::asio::steady_timer timer(io);
  std::function<void()> tick;
  tick = [&]() {
    timer.expires_after(std::chrono::seconds(cfg.stats_every_sec));
    timer.async_wait([&](const boost::system::error_code& ec) {
      if (!ec) {
        std::cout << stats.report_and_reset_interval(cfg.top_talkers, cfg.top_flows, cfg.top_hosts) << "\n";
        tick();
      }
    });
  };
  tick();

  const int workers = std::max(1u, std::thread::hardware_concurrency());
  std::vector<std::thread> pool;
  pool.reserve(workers);
  for (int i = 0; i < workers; i++) pool.emplace_back([&]() { io.run(); });

  PcapCapture cap;
  PcapWriter writer;

  std::thread cap_thread([&]() {
    try {
      cap.run(cfg.iface, cfg.filter, cfg.promisc, cfg.snaplen,
        [&](const PcapPacket& p) {
          if (!cfg.pcap_out.empty() && !writer.enabled() && cap.native_handle() != nullptr) {
            try {
              writer.open(reinterpret_cast<pcap_t*>(cap.native_handle()), cfg.pcap_out);
              std::cerr << "PCAP output enabled: " << cfg.pcap_out << "\n";
            } catch (const std::exception& e) {
              std::cerr << "PCAP output error: " << e.what() << "\n";
            }
          }

          if (writer.enabled()) {
            writer.write(reinterpret_cast<const pcap_pkthdr*>(p.pcap_hdr),
                         reinterpret_cast<const u_char*>(p.data));
          }

          auto buf = std::make_shared<std::vector<uint8_t>>(p.data, p.data + p.caplen);

          boost::asio::post(io, [buf, p, &stats, cfg]() {
            auto parsed = parse_packet(buf->data(), p.caplen, p.wirelen);
            if (!parsed) return;

            stats.ingest(*parsed, now_ms());

            if (cfg.verbose) {
              const auto& x = *parsed;
              std::cout
                << (x.l4 == L4Proto::TCP ? "TCP" : (x.l4 == L4Proto::UDP ? "UDP" : "OTH"))
                << " " << x.src_ip << ":" << x.src_port
                << " -> " << x.dst_ip << ":" << x.dst_port
                << " len=" << x.wirelen;

              if (x.http) {
                std::cout << " | HTTP " << x.http_method << " " << x.http_uri;
                if (!x.http_host.empty()) std::cout << " Host=" << x.http_host;
              }
              std::cout << "\n";
            }
          });
        }
      );
    } catch (const std::exception& e) {
      std::cerr << "Capture error: " << e.what() << "\n";
    }
  });

  std::cout << "Capturing on " << cfg.iface << " with filter: " << cfg.filter << "\n";
  if (!cfg.pcap_out.empty()) std::cout << "PCAP output: " << cfg.pcap_out << "\n";
  std::cout << "Press ENTER to stop...\n";
  std::cin.get();

  cap.stop();
  io.stop();

  cap_thread.join();
  writer.close();
  for (auto& t : pool) t.join();
  return 0;
}
