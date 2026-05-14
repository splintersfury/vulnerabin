void FUN_10001000(void)

{
  undefined4 *puVar1;
  code *pcVar2;
  int *piVar3;
  int *piVar4;
  undefined8 *puVar5;
  int *piVar6;
  undefined4 **ppuVar7;
  int local_f0 [3];
  undefined4 *local_e4 [49];
  undefined4 local_20;
  undefined8 local_1c;
  undefined4 local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004d937;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_e4[0] = (undefined4 *)0xfffffffe;
  ppuVar7 = local_e4;
  local_e4[1] = (undefined4 *)0x14;
  local_e4[2] = (undefined4 *)0xffffffff;
  local_e4[3] = (undefined4 *)0x15;
  local_e4[4] = (undefined4 *)0x2c0;
  local_e4[5] = (undefined4 *)0xb;
  local_e4[6] = (undefined4 *)0x2c1;
  local_e4[7] = (undefined4 *)0xc;
  local_e4[8] = (undefined4 *)0x2c2;
  local_e4[9] = (undefined4 *)0xd;
  local_e4[10] = (undefined4 *)0x2c3;
  local_e4[0xb] = (undefined4 *)0xe;
  local_e4[0xc] = (undefined4 *)0x2c4;
  local_e4[0xd] = (undefined4 *)0xf;
  local_e4[0xe] = (undefined4 *)0x2c6;
  local_e4[0xf] = (undefined4 *)0x10;
  local_e4[0x10] = (undefined4 *)0x2d3;
  local_e4[0x11] = (undefined4 *)0x5;
  local_e4[0x12] = (undefined4 *)0x2d4;
  local_e4[0x13] = (undefined4 *)0x4;
  local_e4[0x14] = (undefined4 *)0x2c5;
  local_e4[0x15] = (undefined4 *)0x12;
  local_e4[0x16] = (undefined4 *)0x2c7;
  local_e4[0x17] = (undefined4 *)0x13;
  local_e4[0x18] = (undefined4 *)0x2f1;
  local_e4[0x19] = (undefined4 *)0x14;
  local_e4[0x1a] = (undefined4 *)0x2f2;
  local_e4[0x1b] = (undefined4 *)0x15;
  local_e4[0x1c] = (undefined4 *)0x2f3;
  local_e4[0x1d] = (undefined4 *)0x6;
  local_e4[0x1e] = (undefined4 *)0x2c9;
  local_e4[0x1f] = (undefined4 *)0x19;
  local_e4[0x20] = (undefined4 *)0x2ca;
  local_e4[0x21] = (undefined4 *)0x1a;
  local_e4[0x22] = (undefined4 *)0x2cb;
  local_e4[0x23] = (undefined4 *)0x1b;
  local_e4[0x24] = (undefined4 *)0x2cc;
  local_e4[0x25] = (undefined4 *)0x1c;
  local_e4[0x26] = (undefined4 *)0x2cd;
  local_e4[0x27] = (undefined4 *)0x1d;
  local_e4[0x28] = (undefined4 *)0x2ce;
  local_e4[0x29] = (undefined4 *)0x1e;
  local_e4[0x2a] = (undefined4 *)0x2cf;
  local_e4[0x2b] = (undefined4 *)0x1f;
  local_e4[0x2c] = (undefined4 *)0x2d0;
  local_e4[0x2d] = (undefined4 *)0x20;
  local_e4[0x2e] = (undefined4 *)0x2f4;
  local_e4[0x2f] = (undefined4 *)0x21;
  piVar4 = (int *)operator_new(0x18);
  *piVar4 = (int)piVar4;
  piVar4[1] = (int)piVar4;
  piVar4[2] = (int)piVar4;
  *(undefined2 *)(piVar4 + 3) = 0x101;
  local_8 = 0;
  DAT_1006b644 = piVar4;
  if (ppuVar7 != local_e4 + 0x30) {
    do {
      puVar5 = (undefined8 *)FUN_10001b50(local_f0,piVar4,(uint *)ppuVar7);
      piVar3 = DAT_1006b644;
      local_1c = *puVar5;
      local_14 = *(undefined4 *)(puVar5 + 1);
      if ((char)local_14 == '\0') {
        if (DAT_1006b648 == 0xaaaaaaa) {
          FUN_10001840();
          pcVar2 = (code *)swi(3);
          (*pcVar2)();
          return;
        }
        local_e4[0x30] = &DAT_1006b644;
        local_8._0_1_ = 1;
        local_20 = 0;
        piVar6 = (int *)operator_new(0x18);
        local_8 = (uint)local_8._1_3_ << 8;
        puVar1 = ppuVar7[1];
        piVar6[4] = (int)*ppuVar7;
        piVar6[5] = (int)puVar1;
        *piVar6 = (int)piVar3;
        piVar6[1] = (int)piVar3;
        piVar6[2] = (int)piVar3;
        *(undefined2 *)(piVar6 + 3) = 0;
        local_20 = 0;
        Insert_node(&DAT_1006b644,(int *)local_1c,local_1c._4_4_,piVar6);
      }
      ppuVar7 = ppuVar7 + 2;
    } while (ppuVar7 != local_e4 + 0x30);
  }
  _atexit((_func_4879 *)&LAB_10050eb0);
  ExceptionList = local_10;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100012e0 @ 100012e0

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */