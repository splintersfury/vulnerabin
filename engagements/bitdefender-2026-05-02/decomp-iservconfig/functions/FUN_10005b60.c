void __thiscall FUN_10005b60(void *this,undefined2 param_1)

{
  undefined2 *puVar1;
  uint uVar2;
  uint uVar3;
  uint *puVar4;
  code *pcVar5;
  uint uVar6;
  uint *puVar7;
  uint uVar8;
  uint *puVar9;
  
  uVar2 = *(uint *)((int)this + 0x14);
  uVar3 = *(uint *)((int)this + 0x10);
  if (uVar3 < uVar2) {
    *(uint *)((int)this + 0x10) = uVar3 + 1;
    if (7 < uVar2) {
                    /* WARNING: Load size is inaccurate */
      this = *this;
    }
    *(undefined2 *)((int)this + uVar3 * 2) = param_1;
    *(undefined2 *)((int)this + uVar3 * 2 + 2) = 0;
    return;
  }
  if (uVar3 == 0x7ffffffe) {
    FUN_10001eb0();
  }
  else {
    uVar8 = uVar3 + 1 | 7;
    if (uVar8 < 0x7fffffff) {
      if (0x7ffffffe - (uVar2 >> 1) < uVar2) {
        uVar8 = 0x7ffffffe;
      }
      else {
        uVar6 = (uVar2 >> 1) + uVar2;
        if (uVar8 < uVar6) {
          uVar8 = uVar6;
        }
      }
    }
    else {
      uVar8 = 0x7ffffffe;
    }
    puVar7 = (uint *)FUN_10001e50(-(uint)(0xfffffffe < uVar8) | uVar8 + 1);
    *(uint *)((int)this + 0x14) = uVar8;
    *(uint *)((int)this + 0x10) = uVar3 + 1;
    uVar3 = uVar3 * 2;
    puVar1 = (undefined2 *)(uVar3 + (int)puVar7);
    if (uVar2 < 8) {
      FUN_100301d0(puVar7,(uint *)this,uVar3);
      *puVar1 = param_1;
      puVar1[1] = 0;
      *(uint **)this = puVar7;
      return;
    }
                    /* WARNING: Load size is inaccurate */
    puVar4 = *this;
    FUN_100301d0(puVar7,puVar4,uVar3);
    *puVar1 = param_1;
    puVar1[1] = 0;
    puVar9 = puVar4;
    if ((uVar2 * 2 + 2 < 0x1000) ||
       (puVar9 = (uint *)puVar4[-1], (uint)((int)puVar4 + (-4 - (int)puVar9)) < 0x20)) {
      FUN_1002e346(puVar9);
      *(uint **)this = puVar7;
      return;
    }
  }
  FUN_10032f7f();
  pcVar5 = (code *)swi(3);
  (*pcVar5)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10005c90 @ 10005c90