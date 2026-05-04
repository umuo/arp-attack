# ArpAttack 自动化云端构建项目

该项目已配置好 GitHub Actions，可以自动在云端构建适配 Windows 7 的 `.exe` 文件。

## 如何获取构建后的 .exe 文件？

1.  **在 GitHub 上创建一个新仓库** (例如命名为 `ArpAttack_Tool`)。
2.  **将此文件夹推送到该仓库**：
    ```bash
    git remote add origin https://github.com/你的用户名/你的仓库名.git
    git branch -M main
    git push -u origin main
    ```
3.  **等待构建**：
    - 前往 GitHub 仓库页面，点击顶部的 **"Actions"** 标签。
    - 你会看到一个正在运行的工作流 "Build ArpAttack for Windows 7"。
    - 等待它显示绿色的勾（大约需要 2-4 分钟）。
4.  **下载文件**：
    - 点击该完成的工作流。
    - 在页面底部的 **"Artifacts"** 栏目下，点击 `ArpAttack_Windows_Executable` 即可下载。

## 注意事项
- 构建环境使用的是 **Python 3.8**，确保了对 Windows 7 的原生支持。
- 运行时仍需在目标机器上安装 **Npcap** 驱动。
