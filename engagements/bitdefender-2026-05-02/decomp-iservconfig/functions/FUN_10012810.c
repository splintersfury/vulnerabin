undefined4 __thiscall FUN_10012810(void *this,int param_1,uint param_2,undefined4 param_3)

{
  uint *puVar1;
  uint uVar2;
  undefined1 uVar3;
  undefined4 uVar4;
  uint uVar5;
  
  uVar2 = param_2;
  uVar5 = 1;
  if (1 < param_2) {
    do {
      *(int *)((int)this + 0x10) = *(int *)((int)this + 0x10) + 1;
      *(int *)((int)this + 0x14) = *(int *)((int)this + 0x14) + 1;
      if (*(char *)((int)this + 0xc) == '\0') {
                    /* WARNING: Load size is inaccurate */
        uVar4 = (**(code **)**this)();
        *(undefined4 *)((int)this + 8) = uVar4;
      }
      else {
        *(undefined1 *)((int)this + 0xc) = 0;
      }
      if (*(int *)((int)this + 8) != -1) {
        puVar1 = *(uint **)((int)this + 0x20);
        uVar3 = (undefined1)*(int *)((int)this + 8);
        param_2 = CONCAT13(uVar3,(undefined3)param_2);
        if (puVar1 == *(uint **)((int)this + 0x24)) {
          FUN_100174f0((void *)((int)this + 0x1c),puVar1,(undefined1 *)((int)&param_2 + 3));
        }
        else {
          *(undefined1 *)puVar1 = uVar3;
          *(int *)((int)this + 0x20) = *(int *)((int)this + 0x20) + 1;
        }
      }
      if (*(int *)((int)this + 8) == 10) {
        *(int *)((int)this + 0x18) = *(int *)((int)this + 0x18) + 1;
        *(undefined4 *)((int)this + 0x14) = 0;
      }
      if (*(int *)((int)this + 8) != (int)*(char *)(uVar5 + param_1)) {
        *(char **)((int)this + 0x40) = "invalid literal";
        return 0xe;
      }
      uVar5 = uVar5 + 1;
    } while (uVar5 < uVar2);
  }
  return param_3;
}


// FUNCTION_END

// FUNCTION_START: FUN_100128b0 @ 100128b0