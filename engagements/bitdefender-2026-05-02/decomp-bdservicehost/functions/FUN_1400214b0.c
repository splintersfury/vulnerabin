longlong *
FUN_1400214b0(longlong *param_1,longlong *param_2,undefined8 *param_3,undefined8 param_4,
             char *param_5)

{
  uint *puVar1;
  char cVar2;
  ulonglong uVar3;
  longlong lVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint *local_48;
  ulonglong uStack_40;
  
  local_48 = (uint *)*param_3;
  uStack_40 = param_3[1];
  uVar3 = FUN_140021640(param_1,(longlong *)&local_48);
  *param_2 = 0;
  param_2[1] = 0;
  *param_2 = *param_1;
  param_2[1] = 0;
  if (((longlong)uVar3 < 0) && ((ulonglong)param_2[1] < -uVar3)) {
    uVar3 = param_2[1] + uVar3;
    lVar4 = (~uVar3 >> 5) * -4 + -4;
  }
  else {
    uVar3 = param_2[1] + uVar3;
    lVar4 = (uVar3 >> 5) << 2;
  }
  *param_2 = *param_2 + lVar4;
  param_2[1] = (ulonglong)((uint)uVar3 & 0x1f);
  local_48 = (uint *)*param_2;
  uStack_40 = param_2[1];
  uVar7 = (uint)(uStack_40 + 1) & 0x1f;
  puVar1 = local_48 + (uStack_40 + 1 >> 5);
  if ((local_48 != puVar1) || (uStack_40 != uVar7)) {
    cVar2 = *param_5;
    uVar5 = -1 << ((byte)uStack_40 & 0x1f);
    if (local_48 == puVar1) {
      uVar6 = 0xffffffff >> (0x20U - (char)uVar7 & 0x1f);
      uVar7 = 0;
      if (cVar2 != '\0') {
        uVar7 = uVar6;
      }
      *local_48 = (~uVar6 | ~uVar5) & *local_48 | uVar7 & uVar5;
    }
    else {
      uVar6 = 0;
      if (cVar2 != '\0') {
        uVar6 = uVar5;
      }
      *local_48 = uVar6 | *local_48 & ~uVar5;
      FUN_140031e00((undefined1 (*) [16])(local_48 + 1),-(*param_5 != '\0'),
                    (longlong)puVar1 - (longlong)(local_48 + 1));
      if ((ulonglong)uVar7 != 0) {
        uVar5 = 0xffffffff >> (0x20U - (char)uVar7 & 0x1f);
        uVar7 = 0;
        if (cVar2 != '\0') {
          uVar7 = uVar5;
        }
        *puVar1 = uVar7 | ~uVar5 & *puVar1;
      }
    }
  }
  return param_2;
}


// FUNCTION_END

// FUNCTION_START: FUN_140021640 @ 140021640