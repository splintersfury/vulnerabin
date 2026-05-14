void __fastcall FUN_10003ad0(uint *******param_1)

{
  int *this;
  uint uVar1;
  char cVar2;
  int iVar3;
  uint ************ppppppppppppuVar4;
  uint *puVar5;
  uint *puVar6;
  int local_1bc [2];
  int local_1b4;
  int local_1b0 [5];
  undefined4 local_19c;
  undefined4 local_198;
  undefined4 local_194;
  undefined4 local_184;
  undefined4 local_180;
  undefined4 local_17c;
  undefined4 local_16c;
  undefined4 local_168;
  uint ***********local_164 [4];
  uint local_154;
  uint local_150;
  undefined4 local_14c;
  undefined4 local_13c;
  undefined4 local_138;
  undefined4 local_134;
  undefined4 local_124;
  undefined4 local_120;
  undefined4 local_11c;
  undefined4 local_10c;
  undefined4 local_108;
  undefined1 local_103;
  undefined1 local_e8;
  undefined1 local_cc;
  undefined1 local_b0;
  undefined4 local_ac;
  undefined4 local_9c;
  undefined4 local_98;
  undefined1 local_7c;
  undefined1 local_60;
  undefined1 local_54;
  undefined4 local_48;
  undefined4 local_44 [4];
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c [4];
  undefined4 local_1c;
  undefined4 local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004dc20;
  local_10 = ExceptionList;
  local_14 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  _memset(&local_48,0,0x34);
  iVar3 = FUN_1001e130();
  local_1b0[0] = 6;
  this = (int *)(iVar3 + 0x60);
  FUN_10023ea0(this,local_1bc,local_1b0);
  if ((*(char *)(local_1b4 + 0xd) != '\0') || (6 < *(int *)(local_1b4 + 0x10))) {
    local_1b4 = *this;
  }
  if (local_1b4 == *this) {
    puVar6 = (uint *)&DAT_10060130;
  }
  else {
    puVar6 = (uint *)(local_1b4 + 0x14);
    if (7 < *(uint *)(local_1b4 + 0x28)) {
      puVar6 = (uint *)*puVar6;
    }
  }
  local_48 = 0x80000002;
  local_34 = 0;
  local_30 = 7;
  local_44[0] = 0;
  puVar5 = puVar6;
  do {
    uVar1 = *puVar5;
    puVar5 = (uint *)((int)puVar5 + 2);
  } while ((short)uVar1 != 0);
  FUN_10001d40(local_44,puVar6,(int)puVar5 - ((int)puVar6 + 2) >> 1);
  local_8 = 0;
  local_1c = 0;
  local_18 = 7;
  local_2c[0] = 0;
  FUN_10001d40(local_2c,(uint *)L"UserInfoEx",10);
  local_19c = 0;
  local_198 = 7;
  local_1b0[1] = 0;
  local_184 = 0;
  local_180 = 7;
  local_194 = 0;
  local_16c = 0;
  local_168 = 7;
  local_17c = 0;
  local_154 = 0;
  local_150 = 7;
  local_164[0] = (uint ***********)0x0;
  local_13c = 0;
  local_138 = 7;
  local_14c = 0;
  local_124 = 0;
  local_120 = 7;
  local_134 = 0;
  local_10c = 0;
  local_108 = 7;
  local_11c = 0;
  local_103 = 0;
  local_e8 = 0;
  local_cc = 0;
  local_b0 = 0;
  local_9c = 0;
  local_98 = 7;
  local_ac = 0;
  local_7c = 0;
  local_60 = 0;
  local_54 = 0;
  local_8 = 2;
  cVar2 = FUN_10024da0(local_1b0 + 1);
  if ((cVar2 != '\0') && ((uint ************)param_1 != local_164)) {
    ppppppppppppuVar4 = local_164;
    if (7 < local_150) {
      ppppppppppppuVar4 = (uint ************)local_164[0];
    }
    FUN_10001d40(param_1,(uint *)ppppppppppppuVar4,local_154);
  }
  FUN_10003e10(local_1b0 + 1);
  FUN_10003d70((int)&local_48);
  ExceptionList = local_10;
  FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10003d70 @ 10003d70