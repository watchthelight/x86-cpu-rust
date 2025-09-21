#[test]
fn workspace_smoke_cpu_core() {
    let mut cpu = cpu_core::Cpu::new();
    // Default CPL is 0 until CS is set explicitly; current API exposes current_cpl via CS cache
    assert_eq!(cpu.current_cpl(), 0);
}

