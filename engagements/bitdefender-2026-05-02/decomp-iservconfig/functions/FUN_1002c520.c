void __thiscall
FUN_1002c520(void *this,IID *param_1,undefined4 param_2,undefined4 param_3,int *param_4)

{
  int *piVar1;
  code *pcVar2;
  IUnknownVtbl **ppIVar3;
  IUnknown *This;
  HRESULT HVar4;
  IUnknown *This_00;
  IUnknown *This_01;
  IUnknown *local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10050df0;
  local_10 = ExceptionList;
  local_14 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_18 = (IUnknown *)0x0;
  FUN_1002c210(&local_18,param_4);
  This = local_18;
  if ((*(int *)(param_4[1] + 4) == DAT_10069aac) && (*param_4 == 0)) {
    if (local_18 == (IUnknown *)0x0) {
      FUN_1002f620(0x80004003);
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    local_8 = 1;
    ppIVar3 = &local_18->lpVtbl;
    local_18 = (IUnknown *)0x0;
    HVar4 = (*(*ppIVar3)[1].QueryInterface)(This,param_1,(void **)0x0);
    This_01 = local_18;
    if (HVar4 == 0) {
      *param_4 = 0;
      param_4[1] = (int)&PTR_vftable_10069aa8;
      local_8 = CONCAT31(local_8._1_3_,2);
      if (local_18 != (IUnknown *)0x0) {
        (*local_18->lpVtbl->AddRef)(local_18);
      }
    }
    else {
      This_01 = (IUnknown *)0x0;
    }
    if ((*(int *)(param_4[1] + 4) == DAT_10069aac) && (*param_4 == 0)) {
      HVar4 = CoSetProxyBlanket(This_01,10,0,(OLECHAR *)0x0,3,3,(RPC_AUTH_IDENTITY_HANDLE)0x0,0);
      if (HVar4 == 0) {
        *param_4 = 0;
        param_4[1] = (int)&PTR_vftable_10069aa8;
                    /* WARNING: Load size is inaccurate */
        if (*this != This) {
          local_8 = 7;
          (*This->lpVtbl->AddRef)(This);
                    /* WARNING: Load size is inaccurate */
          piVar1 = *this;
          *(IUnknown **)this = This;
          local_8 = 8;
          if (piVar1 != (int *)0x0) {
            (**(code **)(*piVar1 + 8))(piVar1);
          }
        }
        This_00 = *(IUnknown **)((int)this + 4);
        if (This_00 != This_01) {
          local_8 = 9;
          if (This_01 != (IUnknown *)0x0) {
            (*This_01->lpVtbl->AddRef)(This_01);
            This_00 = *(IUnknown **)((int)this + 4);
          }
          *(IUnknown **)((int)this + 4) = This_01;
          local_8 = 10;
          if (This_00 != (IUnknown *)0x0) {
            (*This_00->lpVtbl->Release)(This_00);
          }
        }
        local_8 = 0xb;
        if (This_01 != (IUnknown *)0x0) {
          (*This_01->lpVtbl->Release)(This_01);
        }
        local_8 = 0xc;
        (*This->lpVtbl->Release)(This);
      }
      else {
        *param_4 = HVar4;
        param_4[1] = (int)&PTR_vftable_10069ab8;
        local_8 = 5;
        if (This_01 != (IUnknown *)0x0) {
          (*This_01->lpVtbl->Release)(This_01);
        }
        local_8 = 6;
        (*This->lpVtbl->Release)(This);
      }
    }
    else {
      local_8 = 3;
      if (This_01 != (IUnknown *)0x0) {
        (*This_01->lpVtbl->Release)(This_01);
      }
      local_8 = 4;
      (*This->lpVtbl->Release)(This);
    }
  }
  else {
    local_8 = 0;
    if (local_18 != (IUnknown *)0x0) {
      (*local_18->lpVtbl->Release)(local_18);
    }
  }
  ExceptionList = local_10;
  FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1002c71a @ 1002c71a