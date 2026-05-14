undefined8 * FUN_14001cdf0(char *param_1,undefined8 *param_2,undefined8 param_3,undefined8 param_4)

{
  ulonglong uVar1;
  ulonglong uVar2;
  uint uVar3;
  char *pcVar4;
  longlong *plVar5;
  undefined8 *puVar6;
  undefined8 *puVar7;
  undefined8 *_Buf2;
  undefined8 *puVar8;
  ulonglong _Size;
  ulonglong uVar9;
  undefined8 local_e0 [4];
  longlong local_c0 [11];
  undefined8 local_68 [8];
  
  if (*param_1 == '\x01') {
    puVar6 = (undefined8 *)**(longlong **)(param_1 + 8);
    if (*(char *)((longlong)puVar6[1] + 0x19) == '\0') {
      uVar1 = param_2[2];
      uVar2 = param_2[3];
      puVar8 = (undefined8 *)puVar6[1];
      do {
        puVar7 = puVar8 + 4;
        _Buf2 = param_2;
        if (0xf < uVar2) {
          _Buf2 = (undefined8 *)*param_2;
        }
        uVar9 = puVar8[6];
        if (0xf < (ulonglong)puVar8[7]) {
          puVar7 = (undefined8 *)*puVar7;
        }
        _Size = uVar9;
        if (uVar1 < uVar9) {
          _Size = uVar1;
        }
        uVar3 = memcmp(puVar7,_Buf2,_Size);
        if (uVar3 == 0) {
          if (uVar9 < uVar1) {
            uVar3 = 0xffffffff;
          }
          else {
            uVar3 = (uint)(uVar1 < uVar9);
          }
        }
        if ((int)uVar3 < 0) {
          puVar7 = (undefined8 *)puVar8[2];
        }
        else {
          puVar7 = (undefined8 *)*puVar8;
          puVar6 = puVar8;
        }
        puVar8 = puVar7;
      } while (*(char *)((longlong)puVar7 + 0x19) == '\0');
    }
    if (*(char *)((longlong)puVar6 + 0x19) == '\0') {
      puVar8 = puVar6 + 4;
      uVar1 = puVar6[6];
      if (0xf < (ulonglong)puVar6[7]) {
        puVar8 = (undefined8 *)*puVar8;
      }
      uVar2 = param_2[2];
      if (0xf < (ulonglong)param_2[3]) {
        param_2 = (undefined8 *)*param_2;
      }
      uVar9 = uVar2;
      if (uVar1 < uVar2) {
        uVar9 = uVar1;
      }
      uVar3 = memcmp(param_2,puVar8,uVar9);
      if (uVar3 == 0) {
        if (uVar2 < uVar1) {
          uVar3 = 0xffffffff;
        }
        else {
          uVar3 = (uint)(uVar1 < uVar2);
        }
      }
      if (-1 < (int)uVar3) {
        return puVar6 + 8;
      }
    }
    param_1 = "invalid map<K, T> key";
    FUN_14002d718(0x14006c920);
  }
  pcVar4 = FUN_14001ddd0(param_1);
  plVar5 = FUN_14000e950(local_c0,(undefined8 *)pcVar4);
  puVar6 = FUN_140011fa0(local_e0,(undefined8 *)"cannot use at() with ",plVar5,param_4);
  FUN_1400190c0(local_68,0x130,puVar6);
                    /* WARNING: Subroutine does not return */
  _CxxThrowException(local_68,(ThrowInfo *)&DAT_140077cc0);
}


// FUNCTION_END

// FUNCTION_START: FUN_14001cf70 @ 14001cf70