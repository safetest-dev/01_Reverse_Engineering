# hexor.cr

def banner
  puts <<-'EOF'
 _   _  ________  ______  ______
| | | |/ /  ____|/ __ \ \/ / __ \
| |_| ' /| |__  | |  | \  / |  | |
|  _  < |  __| | |  | |\/| |  | |
| | | . \| |____| |__| |  | |__| |
|_| |_|\_\______|\____/|_|\_\____/

        HEX XOR DECODER 🔥
======================================
EOF
end

# parse hex string → bytes (little endian aware)
def parse_hex(input : String)
  hex = input.starts_with?("0x") ? input[2..] : input
  hex = "0" + hex if hex.size.odd?

  bytes = [] of UInt8
  hex.chars.each_slice(2) do |pair|
    bytes << pair.join.to_i(16).to_u8
  end

  bytes.reverse!  # little endian
  bytes
end

# parse XOR key (support 0x.. or decimal)
def parse_key(input : String)
  if input.starts_with?("0x")
    input[2..].to_i(16)
  else
    input.to_i
  end
end

# XOR decode
def xor_decode(bytes : Array(UInt8), key : Int32)
  bytes.map { |b| (b ^ key).chr }.join
end

# filter readable string
def readable?(s : String)
  return false if s.size == 0
  printable = s.count { |c| c.ord >= 32 && c.ord <= 126 }
  printable > s.size * 0.85
end

# brute XOR
def brute_xor(bytes)
  puts "\n[+] Brute forcing XOR keys...\n"
  (1..255).each do |k|
    decoded = xor_decode(bytes, k)
    if readable?(decoded)
      puts "\e[32m[key 0x#{k.to_s(16)}] => #{decoded}\e[0m"
    end
  end
end

# ===== MAIN =====

banner

if ARGV.size == 0
  puts "Usage:"
  puts "  hexor <hex> [xor_key]"
  puts "  hexor <hex> --brute"
  exit
end

input = ARGV[0]

begin
  bytes = parse_hex(input)
rescue
  puts "[!] Invalid hex input"
  exit
end

# brute mode
if ARGV.size > 1 && ARGV[1] == "--brute"
  brute_xor(bytes)
  exit
end

# manual key mode
if ARGV.size > 1
  key = parse_key(ARGV[1])
  result = xor_decode(bytes, key)

  puts "\n[+] XOR key : 0x#{key.to_s(16)}"
  puts "\e[36m[+] Result  : #{result}\e[0m"
else
  puts "\n[!] No XOR key provided. Try --brute"
end
