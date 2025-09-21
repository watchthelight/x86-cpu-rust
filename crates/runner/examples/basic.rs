use cpu_core::{Cpu, SegReg, SegmentCache, SegmentSelector};

fn main() {
    // Create CPU and set flat CS/SS (CPL=3) for a trivial demonstration
    let mut cpu = Cpu::new();
    let mut cs_flags = cpu_core::segments::DescriptorFlags::TYPE
        | cpu_core::segments::DescriptorFlags::EXEC
        | cpu_core::segments::DescriptorFlags::PRESENT
        | cpu_core::segments::DescriptorFlags::DB;
    cs_flags = cpu_core::segments::DescriptorFlags::from_bits_retain(cs_flags.bits() | (0b11 << 5));
    let ds_flags = cpu_core::segments::DescriptorFlags::TYPE
        | cpu_core::segments::DescriptorFlags::RW
        | cpu_core::segments::DescriptorFlags::PRESENT
        | cpu_core::segments::DescriptorFlags::DB;
    cpu.segs.set(
        SegReg::CS,
        SegmentSelector((1 << 3) | 3),
        SegmentCache { base: 0, limit: 0xFFFFF, flags: cs_flags, valid: true },
    );
    cpu.segs.set(
        SegReg::SS,
        SegmentSelector((2 << 3) | 3),
        SegmentCache { base: 0, limit: 0xFFFFF, flags: ds_flags, valid: true },
    );
    println!("cpu initialized, CPL={}", cpu.current_cpl());
}

