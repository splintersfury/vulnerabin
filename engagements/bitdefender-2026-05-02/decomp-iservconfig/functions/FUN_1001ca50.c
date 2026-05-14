void __fastcall
FUN_1001ca50(int param_1,int *param_2,int *param_3,uint param_4,int param_5,undefined4 param_6,
            undefined4 param_7,uint param_8,int param_9,undefined4 param_10,undefined4 param_11,
            uint param_12,uint param_13,int param_14)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  ulonglong uVar10;
  undefined8 local_48;
  int local_34;
  uint local_2c;
  uint local_20;
  uint local_1c;
  uint local_14;
  uint local_10;
  int local_c;
  
  uVar6 = param_12 - param_4;
  uVar2 = (param_13 - param_5) - (uint)(param_12 < param_4);
  local_10 = param_12 - param_8;
  local_14 = (param_13 - param_9) - (uint)(param_12 < param_8);
  uVar5 = -param_14;
  local_2c = 1 << (uVar5 & 0x1f);
  local_20 = 0;
  if (0x1f < uVar5) {
    local_20 = local_2c;
  }
  local_2c = local_2c ^ local_20;
  if (0x3f < uVar5) {
    local_20 = local_2c;
  }
  uVar7 = (local_20 - 1) + (uint)(local_2c != 0);
  uVar9 = (uint)(CONCAT44(param_13,param_12) >> (ulonglong)uVar5);
  uVar3 = local_2c - 1 & param_12;
  local_1c = uVar7 & param_13;
  local_48 = CONCAT44(local_1c,uVar3);
  if (uVar9 < 1000000000) {
    if (uVar9 < 100000000) {
      if (uVar9 < 10000000) {
        if (uVar9 < 1000000) {
          if (uVar9 < 100000) {
            if (uVar9 < 10000) {
              if (uVar9 < 1000) {
                if (uVar9 < 100) {
                  if (uVar9 < 10) {
                    uVar4 = 1;
                    iVar8 = 1;
                  }
                  else {
                    uVar4 = 10;
                    iVar8 = 2;
                  }
                }
                else {
                  uVar4 = 100;
                  iVar8 = 3;
                }
              }
              else {
                uVar4 = 1000;
                iVar8 = 4;
              }
            }
            else {
              uVar4 = 10000;
              iVar8 = 5;
            }
          }
          else {
            uVar4 = 100000;
            iVar8 = 6;
          }
        }
        else {
          uVar4 = 1000000;
          iVar8 = 7;
        }
      }
      else {
        uVar4 = 10000000;
        iVar8 = 8;
      }
    }
    else {
      uVar4 = 100000000;
      iVar8 = 9;
    }
  }
  else {
    uVar4 = 1000000000;
    iVar8 = 10;
  }
  do {
    uVar1 = uVar9 / uVar4;
    uVar9 = uVar9 % uVar4;
    iVar8 = iVar8 + -1;
    uVar10 = ((ulonglong)uVar9 << (ulonglong)uVar5) + local_48;
    *(char *)(param_1 + *param_2) = (char)uVar1 + '0';
    *param_2 = *param_2 + 1;
    local_34 = *param_2;
    if (uVar10 <= CONCAT44(uVar2,uVar6)) {
      *param_3 = *param_3 + iVar8;
      local_48._4_4_ = (uint)(((ulonglong)uVar4 << (ulonglong)uVar5) >> 0x20);
      local_20 = local_48._4_4_;
      local_48._0_4_ = (uint)((ulonglong)uVar4 << (ulonglong)uVar5);
      local_2c = (uint)local_48;
      goto LAB_1001ccfb;
    }
    uVar4 = uVar4 / 10;
  } while (0 < iVar8);
  local_c = 0;
  do {
    do {
      local_1c = (local_1c + (local_1c << 2 | uVar3 >> 0x1e) + (uint)CARRY4(uVar3,uVar3 * 4)) * 2 |
                 uVar3 * 5 >> 0x1f;
      uVar10 = __aullshr(-(char)param_14,local_1c);
      uVar3 = uVar3 * 10 & local_2c - 1;
      local_c = local_c + 1;
      *(char *)(local_34 + param_1) = (char)uVar10 + '0';
      *param_2 = *param_2 + 1;
      local_34 = *param_2;
      local_1c = local_1c & uVar7;
      uVar10 = CONCAT44(local_1c,uVar3);
      uVar2 = (uVar2 + (uVar2 << 2 | uVar6 >> 0x1e) + (uint)CARRY4(uVar6,uVar6 * 4)) * 2 |
              uVar6 * 5 >> 0x1f;
      uVar6 = uVar6 * 10;
      local_14 = (local_14 + (local_14 << 2 | local_10 >> 0x1e) +
                 (uint)CARRY4(local_10,local_10 * 4)) * 2 | local_10 * 5 >> 0x1f;
      local_10 = local_10 * 10;
    } while (uVar2 < local_1c);
  } while ((uVar2 <= local_1c) && (uVar6 < uVar3));
  *param_3 = *param_3 - local_c;
LAB_1001ccfb:
  FUN_1001c9a0(param_1,*param_2,local_10,local_14,uVar6,uVar2,(uint)uVar10,(uint)(uVar10 >> 0x20),
               local_2c,local_20);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001cd30 @ 1001cd30