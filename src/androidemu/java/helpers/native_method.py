import inspect

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_SP
from androidemu.const.emu_const import Arch

from androidemu.java import JavaClassDef
from androidemu.java.jni_ref import jobject


def native_write_args(emu, *argv):
    if emu.get_arch() == Arch.ARM32:
        max_regs_args = 4
        reg_base = UC_ARM_REG_R0
        sp_reg = UC_ARM_REG_SP
    else:
        max_regs_args = 8
        reg_base = UC_ARM64_REG_X0
        sp_reg = UC_ARM64_REG_SP

    ptr_sz = emu.get_ptr_size()
    amount = len(argv)

    nreg = max_regs_args
    if amount < max_regs_args:
        nreg = amount

    for i in range(0, nreg):
        native_write_arg_register(emu, reg_base + i, argv[i])

    if amount > max_regs_args:
        sp_start = emu.mu.reg_read(sp_reg)
        sp_current = sp_start
        # Reserve space for arguments.
        sp_current = sp_current - (ptr_sz * (amount - max_regs_args))
        sp_end = sp_current

        for arg in argv[max_regs_args:]:
            emu.mu.mem_write(
                sp_current,
                native_translate_arg(emu, arg).to_bytes(
                    ptr_sz, "little"
                ),
            )
            sp_current = sp_current + ptr_sz

        emu.mu.reg_write(sp_reg, sp_end)


def native_read_args_in_hook_code(emu, args_count):
    max_regs_args = 4  # 寄存器参数个数
    reg_base = UC_ARM_REG_R0
    sp_reg = UC_ARM_REG_SP

    if emu.get_arch() == Arch.ARM64:
        max_regs_args = 8
        reg_base = UC_ARM64_REG_X0
        sp_reg = UC_ARM64_REG_SP

    ptr_sz = emu.get_ptr_size()

    nreg = max_regs_args
    if args_count < max_regs_args:
        nreg = args_count

    native_args = []
    mu = emu.mu

    for i in range(0, nreg):
        native_args.append(mu.reg_read(reg_base + i))

    if args_count > max_regs_args:
        sp = mu.reg_read(sp_reg)

        for x in range(0, args_count - max_regs_args):
            native_args.append(
                int.from_bytes(
                    mu.mem_read(sp + (x * ptr_sz), ptr_sz), "little"
                )
            )

    return native_args


def native_translate_arg(emu, val):
    if isinstance(val, int):
        return val
    elif isinstance(val, tuple) and len(val) == 2 and all(isinstance(v, int) for v in val):
        return val
    elif isinstance(val, bytearray):
        return emu.java_vm.jni_env.add_local_reference(jobject(val))
    elif isinstance(type(val), JavaClassDef):
        return emu.java_vm.jni_env.add_local_reference(jobject(val))
    else:
        raise NotImplementedError(f"Unable to write response '{str(val)}' type '{type(val)}' to emulator.")


def native_write_arg_register(emu, reg, val):
    emu.mu.reg_write(reg, native_translate_arg(emu, val))


def create_native_method_wrapper(func, args_count):
    def native_method_wrapper(*argv):
        emu = argv[1] if len(argv) == 2 else argv[0]
        mu = emu.mu

        native_args = native_read_args_in_hook_code(emu, args_count)

        if len(argv) == 1:
            result = func(mu, *native_args)
        else:
            result = func(argv[0], mu, *native_args)

        ret_reg0 = UC_ARM_REG_R0
        ret_reg1 = UC_ARM_REG_R1
        if emu.get_arch() == Arch.ARM64:
            ret_reg0 = UC_ARM64_REG_X0
            ret_reg1 = UC_ARM64_REG_X1

        if result is not None:
            if isinstance(result, tuple):
                rlow = result[0]
                rhigh = result[1]
                native_write_arg_register(emu, ret_reg0, rlow)
                native_write_arg_register(emu, ret_reg1, rhigh)
            else:
                native_write_arg_register(emu, ret_reg0, result)

    return native_method_wrapper


def native_method(func):
    args = inspect.getfullargspec(func).args
    args_count = len(args) - 1

    if "self" in args:
        args_count -= 1

    if args_count < 0:
        raise RuntimeError("NativeMethod accept at least (self, mu) or (mu).")

    return create_native_method_wrapper(func, args_count)
