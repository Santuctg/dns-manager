from app.services.system_metrics import parse_cpu, cpu_usage, parse_memory, read_network, collect_metrics


def test_cpu_delta_and_first_invalid_sample():
    assert parse_cpu('cpu  10 0 10 80 0 0 0 0\n') == (100,80)
    assert cpu_usage((100,80),(200,120)) == 60.0
    assert cpu_usage((100,80),(100,80)) is None
    assert cpu_usage((200,180),(100,80)) is None


def test_memory_uses_available_not_free():
    memory=parse_memory('MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 400 kB\n')
    assert memory['used_bytes']==600*1024
    assert memory['usage_percent']==60.0


def test_network_excludes_loopback_and_malformed(tmp_path):
    for name in ('lo','eth0','broken'):
        (tmp_path/name/'statistics').mkdir(parents=True)
        (tmp_path/name/'operstate').write_text('up')
        (tmp_path/name/'statistics/rx_bytes').write_text('123' if name!='broken' else 'invalid')
        (tmp_path/name/'statistics/tx_bytes').write_text('456')
    assert read_network(tmp_path)==[{'name':'eth0','rx_bytes':123,'tx_bytes':456,'operstate':'up'}]


def test_collector_partial_failures_are_graceful(tmp_path, monkeypatch):
    (tmp_path/'stat').write_text('cpu 10 0 10 80\n')
    (tmp_path/'loadavg').write_text('1.00 0.50 0.25 2/100 1\n')
    (tmp_path/'meminfo').write_text('MemTotal: 1000 kB\nMemAvailable: 500 kB\n')
    (tmp_path/'uptime').write_text('120.0 10.0\n')
    net=tmp_path/'interfaces';net.mkdir()
    monkeypatch.setattr('app.services.system_metrics.service_states',lambda:{'nginx':'active'})
    result=collect_metrics(proc=tmp_path,sys_net=net,sample_seconds=0)
    assert result['memory']['usage_percent']==50
    assert result['uptime']['seconds']==120
    assert result['services']['nginx']=='active'
    assert result['cpu']['usage_percent'] is None
