param(
    [string]$BinPath = "c:\Users\Rose\Desktop\ow\GameClientApp.decrypted.bin",
    [string]$OutHeader = "c:\Users\Rose\Desktop\Olympus\include\olympus\codec\v24919\jam_schema_db.hpp",
    [string]$OutSource = "c:\Users\Rose\Desktop\Olympus\src\codec\v24919\jam_schema_db_generated.cpp"
)

$ErrorActionPreference = "Stop"
$bin = [System.IO.File]::ReadAllBytes($BinPath)

function RvaToOff([int64]$rva) {
    if ($rva -ge 0x140000000L) { $rva -= 0x140000000L }
    if ($rva -ge 0x1709000L -and $rva -le 0x1814DFFL) { return [int]($rva - 0x1E00L) }
    if ($rva -ge 0x1382000L -and $rva -le 0x17087A1L) { return [int]($rva - 0x1600L) }
    if ($rva -ge 0x1000L -and $rva -le 0x137EA6BL) { return [int]($rva - 0xC00L) }
    return -1
}

function ReadCString([int64]$rva) {
    $off = RvaToOff $rva
    if ($off -lt 0 -or $off -ge $bin.Length) { return "" }
    $end = $off
    while ($end -lt $bin.Length -and $bin[$end] -ne 0 -and ($end - $off) -lt 128) { $end++ }
    return [System.Text.Encoding]::ASCII.GetString($bin, $off, $end - $off)
}

# 1. Extract all 52 JAMProtocolPool vtables from .rdata (identified by vt[+0x08] == 0x140814660)
$rStart = RvaToOff 0x15B0000L
$rEnd   = RvaToOff 0x1620000L
$pools = New-Object System.Collections.Generic.List[object]
$poolByHash = @{}

# Verified 8 Simulation Plane pools registered in +0x104FA90..+0x104FD95
$simPoolOrder = @{
    "0xE3C778BC" = 0 # ClientInInstance
    "0xF0877B67" = 1 # ClientOutInstance
    "0x469A6C4D" = 2 # ClientInCombat
    "0x94F2C3DB" = 3 # ClientInVoice
    "0xF9AD60EB" = 4 # ClientInStats
    "0xE29BEFBC" = 5 # ClientOutCheats
    "0x494A1C53" = 6 # ClientOutPvP
    "0xDB201097" = 7 # ClientOutStats
}

for ($off = $rStart; $off -le $rEnd - 0x40; $off += 8) {
    $vt08 = [BitConverter]::ToUInt64($bin, $off + 8)
    if ($vt08 -eq ([uint64]0x140814660)) {
        $vt10 = [int64]([BitConverter]::ToUInt64($bin, $off + 0x10) - ([uint64]0x140000000))
        $vt18 = [int64]([BitConverter]::ToUInt64($bin, $off + 0x18) - ([uint64]0x140000000))
        $vt28 = [int64]([BitConverter]::ToUInt64($bin, $off + 0x28) - ([uint64]0x140000000))
        $vt30 = [int64]([BitConverter]::ToUInt64($bin, $off + 0x30) - ([uint64]0x140000000))
        $off18 = RvaToOff $vt18
        if ($off18 -gt 0 -and $bin[$off18] -eq 0xB8) {
            $hash = [BitConverter]::ToUInt32($bin, $off18 + 1)
            $hashKey = "0x{0:X8}" -f $hash
            $off10 = RvaToOff $vt10
            $strRva = 0L
            if ($off10 -gt 0 -and $bin[$off10] -eq 0x48 -and $bin[$off10+1] -eq 0x8D -and $bin[$off10+2] -eq 0x05) {
                $disp = [BitConverter]::ToInt32($bin, $off10 + 3)
                $strRva = $vt10 + 7L + $disp
            }
            $off28 = RvaToOff $vt28
            $startOp = if ($off28 -gt 0 -and $bin[$off28] -eq 0xB8) { [BitConverter]::ToUInt32($bin, $off28 + 1) } else { [uint32]0 }
            $off30 = RvaToOff $vt30
            $endOp = if ($off30 -gt 0 -and $bin[$off30] -eq 0xB8) { [BitConverter]::ToUInt32($bin, $off30 + 1) } else { [uint32]0 }
            $name = ReadCString $strRva
            $simIdx = if ($simPoolOrder.ContainsKey($hashKey)) { $simPoolOrder[$hashKey] } else { -1 }
            $pObj = [PSCustomObject]@{
                VTableRva = [uint32]($off + 0x1600)
                Hash      = $hash
                StartOp   = $startOp
                EndOp     = $endOp
                Name      = $name
                SimIndex  = $simIdx
            }
            $pools.Add($pObj)
            $poolByHash[$hash] = $pObj
        }
    }
}

$sortedPools = $pools | Sort-Object StartOp

# 2. Extract all 371 JAMMessageDesc entries and 477 JAMFieldDesc[] tables from .data
$dStart = RvaToOff 0x1709000L
$dEnd   = RvaToOff 0x1814DFFL
$msgDescs = New-Object System.Collections.Generic.List[object]
$tableQueue = New-Object System.Collections.Generic.Queue[uint32]
$visitedTables = @{}

for ($off = $dStart; $off -le $dEnd - 0x20; $off += 8) {
    $hash = [BitConverter]::ToUInt32($bin, $off + 24)
    if ($poolByHash.ContainsKey($hash)) {
        $msgVa    = [BitConverter]::ToUInt64($bin, $off)
        $protoVa  = [BitConverter]::ToUInt64($bin, $off + 8)
        $fieldsVa = [BitConverter]::ToUInt64($bin, $off + 16)
        $opcode   = [BitConverter]::ToUInt32($bin, $off + 28)
        if ($msgVa -ge ([uint64]0x141382000) -and $msgVa -le ([uint64]0x141708000) -and
            $fieldsVa -ge ([uint64]0x141709000) -and $fieldsVa -le ([uint64]0x141814DFF)) {
            $fRva = [uint32]($fieldsVa - ([uint64]0x140000000))
            $pool = $poolByHash[$hash]
            if ($opcode -ge $pool.StartOp -and $opcode -lt $pool.EndOp) {
                $msgDescs.Add([PSCustomObject]@{
                    DescRva   = [uint32]($off + 0x1E00)
                    FieldsRva = $fRva
                    Hash      = $hash
                    Opcode    = $opcode
                    PoolName  = $pool.Name
                })
                if (-not $visitedTables.ContainsKey($fRva)) {
                    $visitedTables[$fRva] = $true
                    $tableQueue.Enqueue($fRva)
                }
            }
        }
    }
}

$fieldTables = @{}
while ($tableQueue.Count -gt 0) {
    $curRva = $tableQueue.Dequeue()
    $fOff = RvaToOff $curRva
    $rows = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt 256; $i++) {
        $rowOff = $fOff + ($i * 0x28)
        $fType  = [BitConverter]::ToUInt32($bin, $rowOff + 8)
        $sOff   = [BitConverter]::ToUInt32($bin, $rowOff + 12)
        $elSz   = [BitConverter]::ToUInt32($bin, $rowOff + 16)
        $arrCnt = [BitConverter]::ToInt32($bin, $rowOff + 20)
        $subVa  = [BitConverter]::ToUInt64($bin, $rowOff + 24)
        $subRva = if ($subVa -ne ([uint64]0)) { [uint32]($subVa - ([uint64]0x140000000)) } else { [uint32]0 }
        $rows.Add([PSCustomObject]@{
            FieldType = $fType
            Offset    = $sOff
            ElemSize  = $elSz
            ArrayCnt  = $arrCnt
            SubRva    = $subRva
        })
        if ($fType -eq 0x11) { break }
        if ($subRva -ne 0 -and -not $visitedTables.ContainsKey($subRva)) {
            $visitedTables[$subRva] = $true
            $tableQueue.Enqueue($subRva)
        }
    }
    $fieldTables[$curRva] = $rows
}

$sortedTableRvas = $fieldTables.Keys | Sort-Object
$sortedMsgDescs  = $msgDescs | Sort-Object Opcode, Hash

# 3. Write Header: jam_schema_db.hpp
$hdr = @"
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "olympus/codec/v24919/jam_compact_codec.hpp"

namespace olympus::codec::v24919 {

struct JAMPoolSpec {
    const char*   name{nullptr};
    std::uint32_t protocol_hash{0};
    std::uint32_t start_opcode{0};
    std::uint32_t end_opcode{0};
    std::uint32_t vtable_rva{0};
    std::int32_t  sim_pool_index{-1}; // 0..7 for Simulation Sub-Channel 0 pools, -1 for Lobby/Control pools

    [[nodiscard]] constexpr std::uint32_t message_count() const noexcept {
        return (end_opcode >= start_opcode) ? (end_opcode - start_opcode) : 0u;
    }
};

// Complete static database extracted from GameClientApp.exe 0.8.0.24919 (.rdata & .data)
[[nodiscard]] std::span<const JAMPoolSpec> all_jam_pools() noexcept;
[[nodiscard]] std::span<const JAMMessageDesc> all_jam_messages() noexcept;

[[nodiscard]] const JAMPoolSpec* find_jam_pool_by_hash(std::uint32_t protocol_hash) noexcept;
[[nodiscard]] const JAMPoolSpec* find_jam_pool_by_name(std::string_view name) noexcept;
[[nodiscard]] const JAMPoolSpec* find_sim_jam_pool(std::uint8_t sim_pool_index) noexcept;

[[nodiscard]] const JAMMessageDesc* find_jam_message_by_opcode(std::uint32_t opcode) noexcept;
[[nodiscard]] const JAMMessageDesc* find_jam_message(std::uint32_t protocol_hash, std::uint32_t opcode) noexcept;

} // namespace olympus::codec::v24919
"@
[System.IO.File]::WriteAllText($OutHeader, $hdr)

# 4. Write Source: jam_schema_db_generated.cpp
$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('// AUTO-GENERATED by tools/extract_jam_schemas.ps1 from GameClientApp.decrypted.bin (0.8.0.24919)')
[void]$sb.AppendLine('#include "olympus/codec/v24919/jam_schema_db.hpp"')
[void]$sb.AppendLine('#include <algorithm>')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('namespace olympus::codec::v24919 {')
[void]$sb.AppendLine('namespace {')
[void]$sb.AppendLine('')

# Forward declare all 477 field tables so cyclic/forward nested sub_schemas link cleanly
foreach ($tRva in $sortedTableRvas) {
    $cnt = $fieldTables[$tRva].Count
    [void]$sb.AppendLine(("extern const JAMFieldDesc kFields_0x{0:X}[{1}];" -f $tRva, $cnt))
}
[void]$sb.AppendLine('')

# Emit definitions for all 477 field tables
foreach ($tRva in $sortedTableRvas) {
    $rows = $fieldTables[$tRva]
    [void]$sb.AppendLine(("const JAMFieldDesc kFields_0x{0:X}[{1}] = {{" -f $tRva, $rows.Count))
    for ($i = 0; $i -lt $rows.Count; $i++) {
        $r = $rows[$i]
        $subPtr = if ($r.SubRva -ne 0) { "kFields_0x{0:X}" -f $r.SubRva } else { "nullptr" }
        [void]$sb.AppendLine(("    {{ """", static_cast<JAMFieldType>(0x{0:X2}u), 0x{1:X}u, 0x{2:X}u, {3}, {4}, nullptr }}," -f $r.FieldType, $r.Offset, $r.ElemSize, $r.ArrayCnt, $subPtr))
    }
    [void]$sb.AppendLine("};")
}
[void]$sb.AppendLine('')

# Emit all 52 JAMPoolSpec entries sorted by start_opcode
[void]$sb.AppendLine(("constexpr JAMPoolSpec kAllPools[{0}] = {{" -f $sortedPools.Count))
foreach ($p in $sortedPools) {
    [void]$sb.AppendLine(("    {{ ""{0}"", 0x{1:X8}u, {2}u, {3}u, 0x{4:X}u, {5} }}," -f $p.Name, $p.Hash, $p.StartOp, $p.EndOp, $p.VTableRva, $p.SimIndex))
}
[void]$sb.AppendLine("};")
[void]$sb.AppendLine('')

# Emit all 371 JAMMessageDesc entries sorted by opcode
[void]$sb.AppendLine(("const JAMMessageDesc kAllMessages[{0}] = {{" -f $sortedMsgDescs.Count))
foreach ($m in $sortedMsgDescs) {
    $msgName = "{0}_0x{1:X4}" -f $m.PoolName, $m.Opcode
    [void]$sb.AppendLine(("    {{ ""{0}"", ""{1}"", kFields_0x{2:X}, 0x{3:X8}u, 0x{4:X4}u }}," -f $msgName, $m.PoolName, $m.FieldsRva, $m.Hash, $m.Opcode))
}
[void]$sb.AppendLine("};")
[void]$sb.AppendLine('')
[void]$sb.AppendLine('} // namespace')
[void]$sb.AppendLine('')

$lookupCode = @"
std::span<const JAMPoolSpec> all_jam_pools() noexcept {
    return kAllPools;
}

std::span<const JAMMessageDesc> all_jam_messages() noexcept {
    return kAllMessages;
}

const JAMPoolSpec* find_jam_pool_by_hash(std::uint32_t protocol_hash) noexcept {
    for (const auto& pool : kAllPools) {
        if (pool.protocol_hash == protocol_hash) {
            return &pool;
        }
    }
    return nullptr;
}

const JAMPoolSpec* find_jam_pool_by_name(std::string_view name) noexcept {
    for (const auto& pool : kAllPools) {
        if (name == pool.name) {
            return &pool;
        }
    }
    return nullptr;
}

const JAMPoolSpec* find_sim_jam_pool(std::uint8_t sim_pool_index) noexcept {
    for (const auto& pool : kAllPools) {
        if (pool.sim_pool_index == static_cast<std::int32_t>(sim_pool_index)) {
            return &pool;
        }
    }
    return nullptr;
}

const JAMMessageDesc* find_jam_message_by_opcode(std::uint32_t opcode) noexcept {
    auto it = std::lower_bound(
        std::begin(kAllMessages),
        std::end(kAllMessages),
        opcode,
        [](const JAMMessageDesc& desc, std::uint32_t op) {
            return desc.opcode < op;
        });
    if (it != std::end(kAllMessages) && it->opcode == opcode) {
        return &(*it);
    }
    return nullptr;
}

const JAMMessageDesc* find_jam_message(std::uint32_t protocol_hash, std::uint32_t opcode) noexcept {
    for (auto it = std::lower_bound(
             std::begin(kAllMessages),
             std::end(kAllMessages),
             opcode,
             [](const JAMMessageDesc& desc, std::uint32_t op) { return desc.opcode < op; });
         it != std::end(kAllMessages) && it->opcode == opcode;
         ++it) {
        if (it->protocol_hash == protocol_hash) {
            return &(*it);
        }
    }
    return nullptr;
}

} // namespace olympus::codec::v24919
"@
[void]$sb.Append($lookupCode)
[System.IO.File]::WriteAllText($OutSource, $sb.ToString())

Write-Output ("Generated {0} pools, {1} messages, and {2} field tables into {3}" -f $sortedPools.Count, $sortedMsgDescs.Count, $sortedTableRvas.Count, $OutSource)
