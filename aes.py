import os
import sys
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import shutil


class FileEncryptor:
    def __init__(self, key=None, iv=None):
        self.key = key
        self.iv = iv
        self.source_dir = "source"
        self.dist_dir = "dist"

    def set_key_iv(self, key_str, iv_str):
        """设置密钥和IV"""
        # 使用SHA256生成32字节的密钥
        self.key = hashlib.sha256(key_str.encode()).digest()
        # 使用SHA256生成16字节的IV
        iv_hash = hashlib.sha256(iv_str.encode()).digest()
        self.iv = iv_hash[:16]  # AES CBC模式需要16字节IV

    def encrypt_file(self, source_file, dist_file):
        """加密单个文件"""
        try:
            # 读取原始文件
            with open(source_file, 'rb') as f:
                plaintext = f.read()

            # 创建AES加密器
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)

            # 加密数据（自动填充）
            ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

            # 保存加密后的文件
            with open(dist_file, 'wb') as f:
                f.write(ciphertext)

            return True, len(ciphertext)

        except Exception as e:
            print(f"加密文件失败: {source_file} -> {e}")
            return False, 0

    def decrypt_file(self, encrypted_file, output_file):
        """解密单个文件"""
        try:
            # 读取加密文件
            with open(encrypted_file, 'rb') as f:
                ciphertext = f.read()

            # 创建AES解密器
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)

            # 解密数据
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

            # 保存解密后的文件
            with open(output_file, 'wb') as f:
                f.write(plaintext)

            return True, len(plaintext)

        except Exception as e:
            print(f"解密文件失败: {encrypted_file} -> {e}")
            return False, 0

    def ensure_directories(self):
        """确保必要的目录存在"""
        if not os.path.exists(self.source_dir):
            os.makedirs(self.source_dir)
            print(f"创建源文件夹: {self.source_dir}")

        if not os.path.exists(self.dist_dir):
            os.makedirs(self.dist_dir)
            print(f"创建目标文件夹: {self.dist_dir}")

    def get_all_files(self, directory):
        """获取目录中的所有文件（包括子目录）"""
        file_list = []
        for root, dirs, files in os.walk(directory):
            # 排除隐藏文件夹
            dirs[:] = [d for d in dirs if not d.startswith('.')]

            for file in files:
                # 排除隐藏文件和临时文件
                if not file.startswith('.') and not file.endswith(('.pyc', '.tmp')):
                    full_path = os.path.join(root, file)
                    file_list.append(full_path)

        return file_list

    def get_relative_path(self, full_path, base_dir):
        """获取相对于基目录的路径"""
        return os.path.relpath(full_path, base_dir)

    def encrypt_source_to_dist(self):
        """加密source文件夹到dist文件夹"""
        print("=" * 50)
        print("加密: source -> dist")
        print("=" * 50)

        # 确保目录存在
        self.ensure_directories()

        # 获取source文件夹中的所有文件
        source_files = self.get_all_files(self.source_dir)

        if not source_files:
            print(f"源文件夹 {self.source_dir} 中没有文件!")
            return 0

        print(f"找到 {len(source_files)} 个文件需要加密")

        encrypted_count = 0
        total_size = 0
        failed_files = []

        for i, source_file in enumerate(source_files, 1):
            # 计算相对路径
            rel_path = self.get_relative_path(source_file, self.source_dir)

            # 构建目标文件路径（保持相同目录结构）
            dist_file = os.path.join(self.dist_dir, rel_path + '.enc')

            # 确保目标目录存在
            dist_dir = os.path.dirname(dist_file)
            if not os.path.exists(dist_dir):
                os.makedirs(dist_dir)

            print(f"[{i}/{len(source_files)}] 加密: {rel_path}")

            success, size = self.encrypt_file(source_file, dist_file)

            if success:
                encrypted_count += 1
                total_size += size
                print(f"  ✓ -> {os.path.basename(dist_file)}")
            else:
                failed_files.append(source_file)
                print(f"  ✗ 失败")

        print("=" * 50)
        print(f"加密完成!")
        print(f"源文件夹: {self.source_dir}")
        print(f"目标文件夹: {self.dist_dir}")
        print(f"成功加密: {encrypted_count} 个文件")
        print(f"总加密大小: {total_size:,} 字节")

        if failed_files:
            print(f"失败文件: {len(failed_files)} 个")
            for f in failed_files[:5]:
                print(f"  - {os.path.basename(f)}")

        return encrypted_count

    def decrypt_dist_to_current(self):
        """解密dist文件夹到当前路径"""
        print("=" * 50)
        print("解密: dist -> 当前路径")
        print("=" * 50)

        # 确保dist目录存在
        if not os.path.exists(self.dist_dir):
            print(f"目标文件夹 {self.dist_dir} 不存在!")
            return 0

        # 获取dist文件夹中的所有.enc文件
        dist_files = []
        for root, dirs, files in os.walk(self.dist_dir):
            for file in files:
                if file.endswith('.enc'):
                    full_path = os.path.join(root, file)
                    dist_files.append(full_path)

        if not dist_files:
            print(f"目标文件夹 {self.dist_dir} 中没有加密文件(.enc)!")
            return 0

        print(f"找到 {len(dist_files)} 个加密文件")

        decrypted_count = 0
        total_size = 0
        failed_files = []

        for i, dist_file in enumerate(dist_files, 1):
            # 计算相对路径（相对于dist_dir）
            rel_path = self.get_relative_path(dist_file, self.dist_dir)

            # 移除.enc后缀
            original_name = rel_path[:-4] if rel_path.endswith('.enc') else rel_path

            # 构建输出文件路径（在当前目录）
            output_file = os.path.join(os.getcwd(), original_name)

            # 确保输出目录存在
            output_dir = os.path.dirname(output_file)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)

            print(f"[{i}/{len(dist_files)}] 解密: {rel_path}")

            success, size = self.decrypt_file(dist_file, output_file)

            if success:
                decrypted_count += 1
                total_size += size
                print(f"  ✓ -> {original_name}")
            else:
                failed_files.append(dist_file)
                print(f"  ✗ 失败")

        print("=" * 50)
        print(f"解密完成!")
        print(f"源文件夹: {self.dist_dir}")
        print(f"输出到: 当前目录")
        print(f"成功解密: {decrypted_count} 个文件")
        print(f"总解密大小: {total_size:,} 字节")

        if failed_files:
            print(f"失败文件: {len(failed_files)} 个")
            for f in failed_files[:5]:
                print(f"  - {os.path.basename(f)}")

        return decrypted_count

    def clean_dist_folder(self):
        """清理dist文件夹"""
        if os.path.exists(self.dist_dir):
            shutil.rmtree(self.dist_dir)
            print(f"已清理文件夹: {self.dist_dir}")

    def show_file_list(self):
        """显示source和dist文件夹中的文件"""
        print("=" * 50)
        print("文件列表")
        print("=" * 50)

        if os.path.exists(self.source_dir):
            source_files = self.get_all_files(self.source_dir)
            print(f"source 文件夹 ({len(source_files)} 个文件):")
            for file in source_files[:10]:  # 只显示前10个
                rel_path = self.get_relative_path(file, self.source_dir)
                size = os.path.getsize(file)
                print(f"  {rel_path} ({size:,} 字节)")
            if len(source_files) > 10:
                print(f"  ... 还有 {len(source_files) - 10} 个文件")
        else:
            print(f"source 文件夹不存在")

        print()

        if os.path.exists(self.dist_dir):
            dist_files = []
            for root, dirs, files in os.walk(self.dist_dir):
                for file in files:
                    if file.endswith('.enc'):
                        full_path = os.path.join(root, file)
                        dist_files.append(full_path)

            print(f"dist 文件夹 ({len(dist_files)} 个加密文件):")
            for file in dist_files[:10]:  # 只显示前10个
                rel_path = self.get_relative_path(file, self.dist_dir)
                size = os.path.getsize(file)
                print(f"  {rel_path} ({size:,} 字节)")
            if len(dist_files) > 10:
                print(f"  ... 还有 {len(dist_files) - 10} 个文件")
        else:
            print(f"dist 文件夹不存在")

        print()


def main():
    """主函数"""
    # 检查是否安装了必要的库
    try:
        from Crypto.Cipher import AES
    except ImportError:
        print("错误: 需要安装pycryptodome库")
        print("请运行: pip install pycryptodome")
        sys.exit(1)

    encryptor = FileEncryptor()

    print("=" * 60)
    print("文件夹加密/解密工具")
    print("=" * 60)
    print("功能:")
    print("  1. 加密 source 文件夹 -> dist 文件夹")
    print("  2. 解密 dist 文件夹 -> 当前路径")
    print("  3. 显示文件列表")
    print("  4. 清理 dist 文件夹")
    print("  5. 退出")
    print("=" * 60)

    while True:
        print("\n请选择操作 (1-5): ")
        choice = input("> ").strip()

        if choice == '5':
            print("退出程序")
            break

        if choice in ['1', '2']:
            # 获取密钥和IV
            print("\n请输入加密参数:")
            key_input = input("密钥(至少8个字符): ").strip()
            if len(key_input) < 8:
                print("错误: 密钥必须至少8个字符")
                continue

            iv_input = input("初始化向量IV(至少8个字符): ").strip()
            if len(iv_input) < 8:
                print("错误: IV必须至少8个字符")
                continue

            # 设置密钥和IV
            encryptor.set_key_iv(key_input, iv_input)

            if choice == '1':
                # 加密
                confirm = input("确定要加密source文件夹吗？(y/n): ").strip().lower()
                if confirm == 'y':
                    encryptor.encrypt_source_to_dist()
                else:
                    print("操作取消")

            elif choice == '2':
                # 解密
                confirm = input("确定要解密dist文件夹到当前路径吗？(y/n): ").strip().lower()
                if confirm == 'y':
                    encryptor.decrypt_dist_to_current()
                else:
                    print("操作取消")

        elif choice == '3':
            # 显示文件列表
            encryptor.show_file_list()

        elif choice == '4':
            # 清理dist文件夹
            confirm = input("确定要清理dist文件夹吗？(y/n): ").strip().lower()
            if confirm == 'y':
                encryptor.clean_dist_folder()
            else:
                print("操作取消")

        else:
            print("无效选择，请重新输入")


def quick_encrypt_decrypt():
    """快速加密解密模式"""
    # 检查是否安装了必要的库
    try:
        from Crypto.Cipher import AES
    except ImportError:
        print("错误: 需要安装pycryptodome库")
        print("请运行: pip install pycryptodome")
        sys.exit(1)

    encryptor = FileEncryptor()

    print("快速文件夹加密/解密工具")
    print("-" * 40)

    if len(sys.argv) > 1:
        operation = sys.argv[1]

        if operation == 'encrypt':
            if len(sys.argv) < 4:
                print("用法: python encryptor.py encrypt <密钥> <IV>")
                print("示例: python encryptor.py encrypt mypassword123 myiv123456")
                sys.exit(1)

            key_input = sys.argv[2]
            iv_input = sys.argv[3]

            if len(key_input) < 8 or len(iv_input) < 8:
                print("错误: 密钥和IV都必须至少8个字符")
                sys.exit(1)

            encryptor.set_key_iv(key_input, iv_input)
            encryptor.encrypt_source_to_dist()

        elif operation == 'decrypt':
            if len(sys.argv) < 4:
                print("用法: python encryptor.py decrypt <密钥> <IV>")
                print("示例: python encryptor.py decrypt mypassword123 myiv123456")
                sys.exit(1)

            key_input = sys.argv[2]
            iv_input = sys.argv[3]

            if len(key_input) < 8 or len(iv_input) < 8:
                print("错误: 密钥和IV都必须至少8个字符")
                sys.exit(1)

            encryptor.set_key_iv(key_input, iv_input)
            encryptor.decrypt_dist_to_current()

        elif operation == 'help':
            print("用法:")
            print("  交互模式: python encryptor.py")
            print("  快速加密: python encryptor.py encrypt <密钥> <IV>")
            print("  快速解密: python encryptor.py decrypt <密钥> <IV>")
            print("  显示帮助: python encryptor.py help")

        else:
            print(f"未知操作: {operation}")
            print("使用 'help' 查看帮助")
    else:
        # 没有参数，进入交互模式
        main()


if __name__ == "__main__":
    # 如果直接运行，使用快速模式
    quick_encrypt_decrypt()


 # pip install pycryptodome asyncio requests websockets
 # apt install python3 git vim nginx python3-pip