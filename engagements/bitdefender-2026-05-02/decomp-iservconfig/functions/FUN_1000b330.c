undefined4 FUN_1000b330(void)

{
  return 1;
}


// FUNCTION_END

// FUNCTION_START: do_tolower @ 1000b340

/* Library Function - Single Match
    protected: virtual char __thiscall std::ctype<char>::do_tolower(char)const 
   
   Library: Visual Studio 2019 Release */

char __thiscall std::ctype<char>::do_tolower(ctype<char> *this,char param_1)

{
  int iVar1;
  
  iVar1 = __Tolower((uint)(byte)param_1,(_Ctypevec *)(this + 8));
  return (char)iVar1;
}


// FUNCTION_END

// FUNCTION_START: do_tolower @ 1000b360

/* Library Function - Single Match
    protected: virtual char const * __thiscall std::ctype<char>::do_tolower(char *,char const
   *)const 
   
   Library: Visual Studio 2019 Release */

char * __thiscall std::ctype<char>::do_tolower(ctype<char> *this,char *param_1,char *param_2)

{
  int iVar1;
  
  if (param_1 != param_2) {
    do {
      iVar1 = __Tolower((uint)(byte)*param_1,(_Ctypevec *)(this + 8));
      *param_1 = (byte)iVar1;
      param_1 = (char *)((byte *)param_1 + 1);
    } while (param_1 != param_2);
  }
  return (char *)(byte *)param_1;
}


// FUNCTION_END

// FUNCTION_START: do_toupper @ 1000b390

/* Library Function - Single Match
    protected: virtual char __thiscall std::ctype<char>::do_toupper(char)const 
   
   Library: Visual Studio 2019 Release */

char __thiscall std::ctype<char>::do_toupper(ctype<char> *this,char param_1)

{
  int iVar1;
  
  iVar1 = __Toupper((uint)(byte)param_1,(_Ctypevec *)(this + 8));
  return (char)iVar1;
}


// FUNCTION_END

// FUNCTION_START: do_toupper @ 1000b3b0

/* Library Function - Single Match
    protected: virtual char const * __thiscall std::ctype<char>::do_toupper(char *,char const
   *)const 
   
   Library: Visual Studio 2019 Release */

char * __thiscall std::ctype<char>::do_toupper(ctype<char> *this,char *param_1,char *param_2)

{
  int iVar1;
  
  if (param_1 != param_2) {
    do {
      iVar1 = __Toupper((uint)(byte)*param_1,(_Ctypevec *)(this + 8));
      *param_1 = (byte)iVar1;
      param_1 = (char *)((byte *)param_1 + 1);
    } while (param_1 != param_2);
  }
  return (char *)(byte *)param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000b3e0 @ 1000b3e0