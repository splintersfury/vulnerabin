void FUN_100014e0(void)

{
  undefined4 *puVar1;
  code *pcVar2;
  int *piVar3;
  int *piVar4;
  undefined8 *puVar5;
  int *piVar6;
  undefined4 **ppuVar7;
  int local_d0 [3];
  undefined4 *local_c4 [41];
  undefined4 local_20;
  undefined8 local_1c;
  undefined4 local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004e5f7;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_c4[0] = (undefined4 *)0x0;
  ppuVar7 = local_c4;
  local_c4[1] = (undefined4 *)0x66;
  local_c4[2] = (undefined4 *)0x1;
  local_c4[3] = (undefined4 *)0x67;
  local_c4[4] = (undefined4 *)0x2;
  local_c4[5] = (undefined4 *)0x68;
  local_c4[6] = (undefined4 *)0x3;
  local_c4[7] = (undefined4 *)0x69;
  local_c4[8] = (undefined4 *)0x8;
  local_c4[9] = (undefined4 *)0x6a;
  local_c4[10] = (undefined4 *)0x9;
  local_c4[0xb] = (undefined4 *)0x6b;
  local_c4[0xc] = (undefined4 *)0xa;
  local_c4[0xd] = (undefined4 *)0x6c;
  local_c4[0xe] = (undefined4 *)0xb;
  local_c4[0xf] = (undefined4 *)0x6d;
  local_c4[0x10] = (undefined4 *)0xc;
  local_c4[0x11] = (undefined4 *)0x6e;
  local_c4[0x12] = (undefined4 *)0xd;
  local_c4[0x13] = (undefined4 *)0x6f;
  local_c4[0x14] = (undefined4 *)0xe;
  local_c4[0x15] = (undefined4 *)0x70;
  local_c4[0x16] = (undefined4 *)0xf;
  local_c4[0x17] = (undefined4 *)0x71;
  local_c4[0x18] = (undefined4 *)0x10;
  local_c4[0x19] = (undefined4 *)0x72;
  local_c4[0x1a] = (undefined4 *)0x11;
  local_c4[0x1b] = (undefined4 *)0x73;
  local_c4[0x1c] = (undefined4 *)0x12;
  local_c4[0x1d] = (undefined4 *)0x74;
  local_c4[0x1e] = (undefined4 *)0x4;
  local_c4[0x1f] = (undefined4 *)0x75;
  local_c4[0x20] = (undefined4 *)0x35a;
  local_c4[0x21] = (undefined4 *)0x78;
  local_c4[0x22] = (undefined4 *)0x35b;
  local_c4[0x23] = (undefined4 *)0x79;
  local_c4[0x24] = (undefined4 *)0x35c;
  local_c4[0x25] = (undefined4 *)0x7a;
  local_c4[0x26] = (undefined4 *)0x35d;
  local_c4[0x27] = (undefined4 *)0x7b;
  piVar4 = (int *)operator_new(0x18);
  *piVar4 = (int)piVar4;
  piVar4[1] = (int)piVar4;
  piVar4[2] = (int)piVar4;
  *(undefined2 *)(piVar4 + 3) = 0x101;
  local_8 = 0;
  DAT_1006b658 = piVar4;
  if (ppuVar7 != local_c4 + 0x28) {
    do {
      puVar5 = (undefined8 *)FUN_1001aba0(local_d0,piVar4,(uint *)ppuVar7);
      piVar3 = DAT_1006b658;
      local_1c = *puVar5;
      local_14 = *(undefined4 *)(puVar5 + 1);
      if ((char)local_14 == '\0') {
        if (DAT_1006b65c == 0xaaaaaaa) {
          FUN_10001840();
          pcVar2 = (code *)swi(3);
          (*pcVar2)();
          return;
        }
        local_c4[0x28] = &DAT_1006b658;
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
        Insert_node(&DAT_1006b658,(int *)local_1c,local_1c._4_4_,piVar6);
      }
      ppuVar7 = ppuVar7 + 2;
    } while (ppuVar7 != local_c4 + 0x28);
  }
  _atexit((_func_4879 *)&LAB_10050f20);
  ExceptionList = local_10;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10001750 @ 10001750