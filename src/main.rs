mod cli;
mod dns;
mod domains;
mod images;
mod inspect;
mod pcap;
mod provenance;
mod runtime;
mod telemetry;
mod web;

use clap::Parser;

use crate::cli::Cli;

fn main() {
    let cli = Cli::parse();

    // Background PCAP traffic auditor mode
    if let Some(ref pcap_path) = cli.dns_pcap_file {
        pcap::run_pcap_dns_auditor(
            pcap_path,
            cli.dns_proxy_box.as_deref().unwrap_or("unknown"),
            cli.dns_proxy_env.as_deref().unwrap_or("unknown"),
            cli.dns_proxy_workspace.as_deref().unwrap_or("-"),
            cli.dns_proxy_cmd.as_deref().unwrap_or("-"),
            cli.dns_proxy_net.as_deref().unwrap_or("internet"),
            cli.dns_proxy_cmd_file.as_deref(),
            cli.dns_proxy_keep_cmd_file,
            cli.dns_proxy_parent_pid,
        );
        return;
    }

    if cli.list {
        runtime::list_boxes(&cli);
        return;
    }

    if cli.verify {
        runtime::verify_isolation(&cli);
        return;
    }

    if let Some(ref target_box) = cli.inspect {
        inspect::inspect_box_stack(&cli, target_box);
        return;
    }

    if let Some(ref target_box) = cli.attach {
        runtime::attach_box(&cli, target_box);
        return;
    }

    if cli.traffic {
        if let Some(ref out_path) = cli.export_pcap {
            telemetry::export_latest_pcap(out_path, cli.box_filter.as_deref());
        } else if cli.web {
            web::serve_traffic_ui(&cli);
        } else if cli.follow {
            telemetry::follow_traffic(&cli);
        } else {
            telemetry::show_traffic_dashboard(&cli);
        }
        return;
    }

    if let Some(ref domain_query) = cli.trace {
        telemetry::trace_domain(&cli, domain_query);
        return;
    }

    runtime::run_box(&cli);
}
