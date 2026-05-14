uint * __thiscall FUN_1000f950(void *this,uint param_1,undefined2 param_2)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint *puVar4;
  code *pcVar5;
  uint *puVar6;
  uint uVar7;
  uint uVar8;
  uint *puVar9;
  undefined4 *puVar10;
  void *local_8;
  
  uVar7 = *(uint *)((int)this + 0x14);
  iVar3 = *(int *)((int)this + 0x10);
  if (param_1 <= uVar7 - iVar3) {
    *(uint *)((int)this + 0x10) = param_1 + iVar3;
    local_8 = this;
    if (7 < uVar7) {
                    /* WARNING: Load size is inaccurate */
      local_8 = *this;
    }
    if (param_1 != 0) {
      puVar10 = (undefined4 *)((int)local_8 + iVar3 * 2);
      for (uVar7 = param_1 >> 1; uVar7 != 0; uVar7 = uVar7 - 1) {
        *puVar10 = CONCAT22(param_2,param_2);
        puVar10 = puVar10 + 1;
      }
      for (uVar7 = (uint)((param_1 & 1) != 0); uVar7 != 0; uVar7 = uVar7 - 1) {
        *(undefined2 *)puVar10 = param_2;
        puVar10 = (undefined4 *)((int)puVar10 + 2);
      }
    }
    *(undefined2 *)((int)local_8 + (param_1 + iVar3) * 2) = 0;
    return (uint *)this;
  }
  if (0x7ffffffeU - iVar3 < param_1) {
    FUN_10001eb0();
  }
  else {
    uVar1 = iVar3 + param_1;
    uVar8 = uVar1 | 7;
    if (uVar8 < 0x7fffffff) {
      if (0x7ffffffe - (uVar7 >> 1) < uVar7) {
        uVar8 = 0x7ffffffe;
      }
      else {
        uVar2 = (uVar7 >> 1) + uVar7;
        if (uVar8 < uVar2) {
          uVar8 = uVar2;
        }
      }
    }
    else {
      uVar8 = 0x7ffffffe;
    }
    puVar6 = (uint *)FUN_10001e50(-(uint)(0xfffffffe < uVar8) | uVar8 + 1);
    *(uint *)((int)this + 0x10) = uVar1;
    uVar2 = iVar3 * 2;
    *(uint *)((int)this + 0x14) = uVar8;
    if (uVar7 < 8) {
      FUN_100301d0(puVar6,(uint *)this,uVar2);
      if (param_1 != 0) {
        puVar10 = (undefined4 *)(uVar2 + (int)puVar6);
        for (uVar7 = param_1 >> 1; uVar7 != 0; uVar7 = uVar7 - 1) {
          *puVar10 = CONCAT22(param_2,param_2);
          puVar10 = puVar10 + 1;
        }
        for (uVar7 = (uint)((param_1 & 1) != 0); uVar7 != 0; uVar7 = uVar7 - 1) {
          *(undefined2 *)puVar10 = param_2;
          puVar10 = (undefined4 *)((int)puVar10 + 2);
        }
      }
      *(undefined2 *)((int)puVar6 + uVar1 * 2) = 0;
      *(uint **)this = puVar6;
      return (uint *)this;
    }
                    /* WARNING: Load size is inaccurate */
    puVar4 = *this;
    FUN_100301d0(puVar6,puVar4,uVar2);
    if (param_1 != 0) {
      puVar10 = (undefined4 *)(uVar2 + (int)puVar6);
      for (uVar8 = param_1 >> 1; uVar8 != 0; uVar8 = uVar8 - 1) {
        *puVar10 = CONCAT22(param_2,param_2);
        puVar10 = puVar10 + 1;
      }
      for (uVar8 = (uint)((param_1 & 1) != 0); uVar8 != 0; uVar8 = uVar8 - 1) {
        *(undefined2 *)puVar10 = param_2;
        puVar10 = (undefined4 *)((int)puVar10 + 2);
      }
    }
    *(undefined2 *)((int)puVar6 + uVar1 * 2) = 0;
    puVar9 = puVar4;
    if ((uVar7 * 2 + 2 < 0x1000) ||
       (puVar9 = (uint *)puVar4[-1], (uint)((int)puVar4 + (-4 - (int)puVar9)) < 0x20)) {
      FUN_1002e346(puVar9);
      *(uint **)this = puVar6;
      return (uint *)this;
    }
  }
  FUN_10032f7f();
  pcVar5 = (code *)swi(3);
  puVar6 = (uint *)(*pcVar5)();
  return puVar6;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000fb00 @ 1000fb00