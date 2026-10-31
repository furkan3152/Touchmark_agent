import { exec } from 'child_process';

export class Soroban {
  constructor(private serverUrl: string) {}

  async buildAndOptimize(args: { contractPath: string }) {
    return new Promise((resolve) => {
      const command = `stellar contract build --manifest-path ${args.contractPath}/Cargo.toml`;
      exec(command, (error, stdout, stderr) => resolve({ stdout, stderr }));
    });
  }
}
