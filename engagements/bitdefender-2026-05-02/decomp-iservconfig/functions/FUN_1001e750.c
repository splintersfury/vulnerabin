void FUN_1001e750(uint *param_1)

{
  char cVar1;
  code *pcVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  uint uVar7;
  uint **ppuVar8;
  uint *puVar9;
  int *piVar10;
  int *piVar11;
  void *pvVar12;
  void *pvVar13;
  uint in_stack_00000014;
  uint in_stack_00000018;
  uint *in_stack_0000001c;
  uint in_stack_0000002c;
  uint in_stack_00000030;
  uint *in_stack_00000034;
  uint in_stack_00000044;
  uint in_stack_00000048;
  uint *in_stack_0000004c;
  uint in_stack_0000005c;
  uint in_stack_00000060;
  void **ppvVar14;
  int local_508 [24];
  undefined **local_4a8 [18];
  void *local_460 [5];
  uint local_44c;
  undefined1 local_445;
  int local_444;
  undefined1 local_440 [1052];
  uint local_24;
  undefined1 *puStack_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_20 = &stack0xfffffffc;
  puStack_18 = &LAB_1004fbd3;
  local_1c = ExceptionList;
  uVar7 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  ExceptionList = &local_1c;
  local_14 = 0;
  local_24 = uVar7;
  FUN_1000c210(local_440,L"ProductInfo::Init");
  local_14._0_1_ = 1;
  ppuVar8 = &param_1;
  if (7 < in_stack_00000018) {
    ppuVar8 = (uint **)param_1;
  }
  FUN_10001d40(&DAT_1006b6c0,(uint *)ppuVar8,in_stack_00000014);
  puVar9 = (uint *)&stack0x0000001c;
  if (7 < in_stack_00000030) {
    puVar9 = in_stack_0000001c;
  }
  FUN_10001d40(&DAT_1006b6d8,puVar9,in_stack_0000002c);
  puVar9 = (uint *)&stack0x00000034;
  if (7 < in_stack_00000048) {
    puVar9 = in_stack_00000034;
  }
  FUN_10001d40(&DAT_1006b6f0,puVar9,in_stack_00000044);
  puVar9 = (uint *)&stack0x0000004c;
  if (7 < in_stack_00000060) {
    puVar9 = in_stack_0000004c;
  }
  FUN_10001d40(&DAT_1006b708,puVar9,in_stack_0000005c);
  piVar10 = FUN_100034b0(local_508,0x10,0x10060134);
  local_14._0_1_ = 2;
  if ((char)piVar10[0x12] != '\0') {
    FUN_10024240(piVar10);
  }
  FUN_10003240((int)local_4a8);
  local_14._0_1_ = 3;
  local_4a8[0] = std::ios_base::vftable;
  std::ios_base::_Ios_base_dtor((ios_base *)local_4a8);
  local_14._0_1_ = 1;
  local_444 = 1;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)"ProductAgentService",0x13);
  local_444 = 2;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)"Product Agent Service description",0x21);
  local_444 = 3;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)"Product Agent Service",0x15);
  local_444 = 4;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)"com.bitdefender",0xf);
  local_444 = 5;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)"com.bitdefender.agent",0x15);
  local_444 = 6;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)"SOFTWARE\\Bitdefender Agent",0x1a);
  local_444 = 7;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)"SOFTWARE\\Bitdefender Agent\\Modules",0x22);
  local_444 = 8;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)
                       "http://download.bitdefender.com/windows/desktop/connect/cl/2016/update.json"
               ,0x4b);
  local_444 = 10;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)&DAT_1005ff60,1);
  local_444 = 0xb;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)"https://login.bitdefender.com/classicLine/",0x2a);
  local_444 = 0xc;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)"native://com.bitdefender.agent",0x1e);
  local_444 = 0xd;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)&DAT_1005ff60,1);
  local_444 = 0xe;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)&DAT_1005e237,0);
  local_444 = 0xf;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)"https://login.bitdefender.com/classicLine/signup.html",0x35);
  local_444 = 0x10;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)"https://arca.bitdefender.com/",0x1d);
  local_444 = 0x11;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)&DAT_1005ff5c,1);
  local_444 = 0x12;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)&DAT_1005e237,0);
  local_444 = 0x13;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)&DAT_10060008,2);
  local_444 = 0x14;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)"en-US",5);
  local_444 = 0x15;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)&DAT_100600c4,3);
  local_444 = 0x22;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)"SOFTWARE\\Bitdefender\\About",0x1a);
  local_444 = 0x23;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)"Bitdefender\\Bitdefender Security",0x20);
  local_444 = 0x24;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)"Bitdefender\\Bitdefender Security App",0x24);
  local_444 = 0x25;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)"com.bitdefender.agent",0x15);
  local_444 = 0x19;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)"com.bitdefender.agent",0x15);
  local_444 = 0x1a;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)"Bitdefender Login",0x11);
  local_444 = 0x1b;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)"BitdefenderLogin.exe",0x14);
  local_444 = 0xb;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)"https://login.bitdefender.com/logout",0x24);
  local_444 = 0xc;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)"com.bitdefender.agent://com.bitdefender.agent.login",0x33);
  local_444 = 0xd;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)&DAT_1005ff60,1);
  local_444 = 0xe;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)&DAT_1005e237,0);
  local_444 = 0xf;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)"https://login.bitdefender.com/signup",0x24);
  local_444 = 9;
  piVar10 = FUN_10021fc0(&DAT_1006b728,&local_444);
  FUN_10008e70(piVar10,(uint *)&DAT_1005ff5c,1);
  piVar10 = (int *)*DAT_1006b728;
  if (piVar10 != DAT_1006b728) {
    do {
      piVar11 = piVar10 + 5;
      if (0xf < (uint)piVar10[10]) {
        piVar11 = (int *)*piVar11;
      }
      FUN_1001c8a0(local_460,(LPCSTR)piVar11,uVar7);
      ppvVar14 = local_460;
      local_14._0_1_ = 4;
      piVar11 = FUN_10022090(&DAT_1006b720,piVar10 + 4);
      FUN_10005380(piVar11,(int *)ppvVar14);
      local_14._0_1_ = 1;
      if (7 < local_44c) {
        pvVar13 = local_460[0];
        if ((0xfff < local_44c * 2 + 2) &&
           (pvVar13 = *(void **)((int)local_460[0] + -4),
           0x1f < (uint)((int)local_460[0] + (-4 - (int)pvVar13)))) goto LAB_1001f2dc;
        FUN_1002e346(pvVar13);
      }
      piVar11 = (int *)piVar10[2];
      if (*(char *)((int)piVar11 + 0xd) == '\0') {
        cVar1 = *(char *)(*piVar11 + 0xd);
        piVar10 = piVar11;
        piVar11 = (int *)*piVar11;
        while (cVar1 == '\0') {
          cVar1 = *(char *)(*piVar11 + 0xd);
          piVar10 = piVar11;
          piVar11 = (int *)*piVar11;
        }
      }
      else {
        cVar1 = *(char *)(piVar10[1] + 0xd);
        piVar6 = (int *)piVar10[1];
        piVar11 = piVar10;
        while ((piVar10 = piVar6, cVar1 == '\0' && (piVar11 == (int *)piVar10[2]))) {
          cVar1 = *(char *)(piVar10[1] + 0xd);
          piVar6 = (int *)piVar10[1];
          piVar11 = piVar10;
        }
      }
    } while (piVar10 != DAT_1006b728);
  }
  FUN_1000eb70(local_460,(uint *)&DAT_1006b6d8);
  ppvVar14 = local_460;
  local_14._0_1_ = 5;
  local_444 = 0;
  piVar10 = FUN_10022090(&DAT_1006b720,&local_444);
  FUN_10005380(piVar10,(int *)ppvVar14);
  local_14._0_1_ = 1;
  if (7 < local_44c) {
    pvVar13 = local_460[0];
    if ((local_44c * 2 + 2 < 0x1000) ||
       (pvVar13 = *(void **)((int)local_460[0] + -4),
       (uint)((int)local_460[0] + (-4 - (int)pvVar13)) < 0x20)) {
      FUN_1002e346(pvVar13);
      goto LAB_1001ef09;
    }
LAB_1001f2dc:
    local_14._0_1_ = 1;
    FUN_10032f7f();
LAB_1001f2e1:
    FUN_10032f7f();
LAB_1001f2e6:
    FUN_10032f7f();
LAB_1001f2eb:
    FUN_10032f7f();
LAB_1001f2f0:
    FUN_10032f7f();
LAB_1001f2f5:
    FUN_10032f7f();
    pcVar2 = (code *)swi(3);
    (*pcVar2)();
    return;
  }
LAB_1001ef09:
  piVar10 = (int *)FUN_1001bfe0(&DAT_1006b6d8,(LPSTR)local_460);
  local_14._0_1_ = 6;
  local_444 = 0;
  piVar11 = FUN_10021fc0(&DAT_1006b728,&local_444);
  if (piVar11 != piVar10) {
    if (0xf < (uint)piVar11[5]) {
      pvVar13 = (void *)*piVar11;
      pvVar12 = pvVar13;
      if ((0xfff < piVar11[5] + 1U) &&
         (pvVar12 = *(void **)((int)pvVar13 + -4), 0x1f < (uint)((int)pvVar13 + (-4 - (int)pvVar12))
         )) goto LAB_1001f2e1;
      FUN_1002e346(pvVar12);
    }
    piVar11[4] = 0;
    piVar11[5] = 0xf;
    *(undefined1 *)piVar11 = 0;
    iVar3 = piVar10[1];
    iVar4 = piVar10[2];
    iVar5 = piVar10[3];
    *piVar11 = *piVar10;
    piVar11[1] = iVar3;
    piVar11[2] = iVar4;
    piVar11[3] = iVar5;
    *(undefined8 *)(piVar11 + 4) = *(undefined8 *)(piVar10 + 4);
    piVar10[4] = 0;
    piVar10[5] = 0xf;
    *(CHAR *)piVar10 = '\0';
  }
  local_14._0_1_ = 1;
  if (0xf < local_44c) {
    pvVar13 = local_460[0];
    if ((0xfff < local_44c + 1) &&
       (pvVar13 = *(void **)((int)local_460[0] + -4),
       0x1f < (uint)((int)local_460[0] + (-4 - (int)pvVar13)))) goto LAB_1001f2e1;
    FUN_1002e346(pvVar13);
  }
  FUN_1000eb70(local_460,(uint *)&DAT_1006b6f0);
  ppvVar14 = local_460;
  local_14._0_1_ = 7;
  local_444 = 0x21;
  piVar10 = FUN_10022090(&DAT_1006b720,&local_444);
  FUN_10005380(piVar10,(int *)ppvVar14);
  local_14._0_1_ = 1;
  if (7 < local_44c) {
    pvVar13 = local_460[0];
    if ((0xfff < local_44c * 2 + 2) &&
       (pvVar13 = *(void **)((int)local_460[0] + -4),
       0x1f < (uint)((int)local_460[0] + (-4 - (int)pvVar13)))) goto LAB_1001f2e6;
    FUN_1002e346(pvVar13);
  }
  piVar10 = (int *)FUN_1001bfe0(&DAT_1006b6f0,(LPSTR)local_460);
  local_14._0_1_ = 8;
  local_444 = 0x21;
  piVar11 = FUN_10021fc0(&DAT_1006b728,&local_444);
  if (piVar11 != piVar10) {
    if (0xf < (uint)piVar11[5]) {
      pvVar13 = (void *)*piVar11;
      pvVar12 = pvVar13;
      if ((0xfff < piVar11[5] + 1U) &&
         (pvVar12 = *(void **)((int)pvVar13 + -4), 0x1f < (uint)((int)pvVar13 + (-4 - (int)pvVar12))
         )) goto LAB_1001f2eb;
      FUN_1002e346(pvVar12);
    }
    piVar11[4] = 0;
    piVar11[5] = 0xf;
    *(undefined1 *)piVar11 = 0;
    iVar3 = piVar10[1];
    iVar4 = piVar10[2];
    iVar5 = piVar10[3];
    *piVar11 = *piVar10;
    piVar11[1] = iVar3;
    piVar11[2] = iVar4;
    piVar11[3] = iVar5;
    *(undefined8 *)(piVar11 + 4) = *(undefined8 *)(piVar10 + 4);
    piVar10[4] = 0;
    piVar10[5] = 0xf;
    *(CHAR *)piVar10 = '\0';
  }
  local_14._0_1_ = 1;
  if (0xf < local_44c) {
    pvVar13 = local_460[0];
    if ((0xfff < local_44c + 1) &&
       (pvVar13 = *(void **)((int)local_460[0] + -4),
       0x1f < (uint)((int)local_460[0] + (-4 - (int)pvVar13)))) goto LAB_1001f2eb;
    FUN_1002e346(pvVar13);
  }
  FUN_1000eb70(local_460,(uint *)&DAT_1006b6f0);
  ppvVar14 = local_460;
  local_14._0_1_ = 9;
  local_444 = 0x21;
  piVar10 = FUN_10022090(&DAT_1006b720,&local_444);
  FUN_10005380(piVar10,(int *)ppvVar14);
  local_14._0_1_ = 1;
  if (7 < local_44c) {
    pvVar13 = local_460[0];
    if ((0xfff < local_44c * 2 + 2) &&
       (pvVar13 = *(void **)((int)local_460[0] + -4),
       0x1f < (uint)((int)local_460[0] + (-4 - (int)pvVar13)))) goto LAB_1001f2f0;
    FUN_1002e346(pvVar13);
  }
  piVar10 = (int *)FUN_1001bfe0(&DAT_1006b6f0,(LPSTR)local_460);
  local_14._0_1_ = 10;
  local_444 = 0x21;
  piVar11 = FUN_10021fc0(&DAT_1006b728,&local_444);
  if (piVar11 != piVar10) {
    if (0xf < (uint)piVar11[5]) {
      pvVar13 = (void *)*piVar11;
      pvVar12 = pvVar13;
      if ((0xfff < piVar11[5] + 1U) &&
         (pvVar12 = *(void **)((int)pvVar13 + -4), 0x1f < (uint)((int)pvVar13 + (-4 - (int)pvVar12))
         )) goto LAB_1001f2f5;
      FUN_1002e346(pvVar12);
    }
    piVar11[4] = 0;
    piVar11[5] = 0xf;
    *(undefined1 *)piVar11 = 0;
    iVar3 = piVar10[1];
    iVar4 = piVar10[2];
    iVar5 = piVar10[3];
    *piVar11 = *piVar10;
    piVar11[1] = iVar3;
    piVar11[2] = iVar4;
    piVar11[3] = iVar5;
    *(undefined8 *)(piVar11 + 4) = *(undefined8 *)(piVar10 + 4);
    piVar10[4] = 0;
    piVar10[5] = 0xf;
    *(CHAR *)piVar10 = '\0';
  }
  local_14._0_1_ = 1;
  if (0xf < local_44c) {
    pvVar13 = local_460[0];
    if ((0xfff < local_44c + 1) &&
       (pvVar13 = *(void **)((int)local_460[0] + -4),
       0x1f < (uint)((int)local_460[0] + (-4 - (int)pvVar13)))) goto LAB_1001f2f5;
    FUN_1002e346(pvVar13);
  }
  local_445 = FUN_1001f300();
  FUN_1000c320((int)local_440);
  FUN_1001e3b0((int *)&param_1);
  ExceptionList = local_1c;
  FUN_1002e315(local_24 ^ (uint)&stack0xfffffff0);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001f300 @ 1001f300