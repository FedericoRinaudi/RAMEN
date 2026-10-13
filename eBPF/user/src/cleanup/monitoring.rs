use std::fs;

pub fn get_cpu_usage() -> Result<f32, Box<dyn std::error::Error>> {
    let stat = fs::read_to_string("/proc/stat")?;
    let cpu_line = stat.lines()
        .next()
        .ok_or("CPU line not found")?;
    
    let values: Vec<u64> = cpu_line
        .split_whitespace()
        .skip(1) // skip "cpu"
        .filter_map(|s| s.parse().ok())
        .collect();
    
    if values.len() < 4 {
        return Err("Invalid CPU data".into());
    }
    
    let idle = values[3];
    let total: u64 = values.iter().sum();
    
    if total == 0 {
        return Ok(0.0);
    }
    
    let usage = 100.0 * (1.0 - (idle as f32 / total as f32));
    Ok(usage)
}
