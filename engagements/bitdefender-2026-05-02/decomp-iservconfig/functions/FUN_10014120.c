uint * __fastcall FUN_10014120(uint *param_1,uint *param_2,uint *param_3)

{
  uint uVar1;
  code *pcVar2;
  uint uVar3;
  void *pvVar4;
  uint uVar5;
  uint uVar6;
  uint *puVar7;
  uint uVar8;
  uint *local_10;
  
  local_10 = param_3;
  puVar7 = param_2;
  do {
    uVar3 = *puVar7;
    puVar7 = (uint *)((int)puVar7 + 1);
  } while ((char)uVar3 != '\0');
  uVar3 = param_3[4];
  uVar8 = (int)puVar7 - ((int)param_2 + 1);
  if (uVar8 <= 0x7fffffff - uVar3) {
    if (0xf < param_3[5]) {
      local_10 = (uint *)*param_3;
    }
    uVar1 = uVar8 + uVar3;
    *param_1 = 0;
    uVar6 = 0xf;
    param_1[4] = 0;
    param_1[5] = 0;
    puVar7 = param_1;
    if (uVar1 < 0x10) goto LAB_10014201;
    uVar6 = uVar1 | 0xf;
    if (uVar6 < 0x80000000) {
      if (uVar6 < 0x16) {
        uVar6 = 0x16;
      }
    }
    else {
      uVar6 = 0x7fffffff;
    }
    uVar5 = -(uint)(0xfffffffe < uVar6) | uVar6 + 1;
    if (uVar5 < 0x1000) {
      if (uVar5 == 0) {
        puVar7 = (uint *)0x0;
      }
      else {
        puVar7 = (uint *)operator_new(uVar5);
      }
    }
    else {
      if (uVar5 + 0x23 <= uVar5) goto LAB_10014239;
      pvVar4 = operator_new(uVar5 + 0x23);
      if (pvVar4 == (void *)0x0) goto LAB_1001423e;
      puVar7 = (uint *)((int)pvVar4 + 0x23U & 0xffffffe0);
      puVar7[-1] = (uint)pvVar4;
    }
    *param_1 = (uint)puVar7;
LAB_10014201:
    param_1[4] = uVar1;
    param_1[5] = uVar6;
    FUN_100301d0(puVar7,param_2,uVar8);
    FUN_100301d0((uint *)((int)puVar7 + uVar8),local_10,uVar3);
    *(undefined1 *)((int)puVar7 + uVar1) = 0;
    return param_1;
  }
  FUN_10001eb0();
LAB_10014239:
  FUN_10001fb0();
LAB_1001423e:
  FUN_10032f7f();
  pcVar2 = (code *)swi(3);
  puVar7 = (uint *)(*pcVar2)();
  return puVar7;
}


// FUNCTION_END

// FUNCTION_START: FUN_10014250 @ 10014250