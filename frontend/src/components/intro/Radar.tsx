// 회전하는 레이더. 순수 장식이다.

export default function Radar({ className, style }: { className?: string; style?: React.CSSProperties }) {
  return (
    <div className={`ix-radar ${className ?? ""}`} style={style} aria-hidden="true">
      <div className="rings" />
      <div className="sweep" />
      <div className="edge" />
      <span className="blip" style={{ width: 8, height: 8, top: "34%", left: "58%", animation: "k-blip 3.6s ease-out infinite" }} />
      <span className="blip" style={{ width: 6, height: 6, top: "62%", left: "36%", animation: "k-blip 4.4s 1.3s ease-out infinite" }} />
      <span className="blip" style={{ width: 6, height: 6, top: "48%", left: "72%", background: "#7cc8ff", animation: "k-blip 5.2s 2.4s ease-out infinite" }} />
    </div>
  );
}
