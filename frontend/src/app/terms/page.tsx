import type { Metadata } from "next";
import LegalPage from "@/components/legal/LegalPage";

export const metadata: Metadata = {
  title: "Términos de uso — GUARDIA FLOW",
  description:
    "Condiciones de uso de Guardia Flow: precio, prueba gratuita de 3 días, renovación mensual, cancelación y uso aceptable.",
};

export default function TermsPage() {
  return (
    <LegalPage
      title="Términos de uso"
      updated="17 de octubre de 2026"
      sections={[
        {
          heading: "El responsable del servicio",
          body: "Guardia Flow es operado por [Nombre legal o razón social], con domicilio en [Dirección fiscal completa], [País]. Identificación fiscal: [RFC / ID fiscal]. Contacto legal: soporte@guardiaflow.com. Estos términos se rigen por las leyes de [País / jurisdicción elegida] y, en lo que no contradiga la legislación local del consumidor, cualquier controversia se someterá a los tribunales competentes de [Ciudad, País].",
        },
        {
          heading: "El servicio",
          body: "Guardia Flow es una herramienta de análisis de seguridad pensada para personas sin conocimientos técnicos: analiza enlaces, correos, mensajes, códigos QR, archivos, imágenes y audio en busca de señales de phishing, estafas, suplantación y manipulación, además de verificar filtraciones de datos y consultar inteligencia de amenazas. Al registrarte y usar Guardia Flow aceptas estos términos.",
        },
        {
          heading: "Precio, prueba gratuita y renovación",
          body: "Guardia Flow Pro cuesta US$16 por mes, cobrados de forma mensual. Al crear tu cuenta obtienes una prueba gratuita de 3 días desde el momento del registro. El primer cobro se realiza al terminar la prueba y la fecha exacta se muestra en tu panel. La suscripción se renueva automáticamente cada mes; al renovar se cobra el precio del plan (US$16) salvo que la canceles antes.",
        },
        {
          heading: "Cancelación",
          body: "Puedes cancelar tu suscripción en cualquier momento desde tu panel (portal de facturación) o escribiéndonos a soporte@guardiaflow.com. Si cancelas durante la prueba gratuita, no se realiza ningún cargo. Si cancelas con la suscripción activa, la cancelación tiene efecto al final del período de facturación en curso: conservas el acceso hasta esa fecha. No se realizan reembolsos de períodos parcialmente usados, salvo obligación legal.",
        },
        {
          heading: "Procesamiento de pagos",
          body: "Los pagos se procesan a través de Stripe. Guardia Flow no almacena los datos de tu tarjeta; la gestión del método de pago, las facturas y la cancelación de la suscripción se realizan a través del portal seguro de Stripe. Al suscribirte, Stripe puede aplicar sus propios términos y políticas de privacidad.",
        },
        {
          heading: "Limitaciones del servicio",
          body: "Guardia Flow se proporciona «tal cual». Ningún producto de seguridad detecta el 100% de las amenazas: los análisis pueden tener falsos positivos y falsos negativos. El análisis de manipulación con IA se basa en metadatos y no constituye una prueba forense. Los resultados son una ayuda para tomar decisiones y no sustituyen el criterio profesional, una auditoría de seguridad ni asesoría legal.",
        },
        {
          heading: "Uso aceptable",
          body: "Guardia Flow debe usarse para la defensa de tus propias cuentas, dispositivos y datos. Está prohibido usar el servicio para analizar, escanear o sondear sistemas de terceros sin su autorización, para acosar, espiar o vigilar personas, o para cualquier propósito ilegal. El incumplimiento puede derivar en la suspensión o cancelación de tu cuenta.",
        },
        {
          heading: "Tu cuenta",
          body: "Eres responsable de mantener la confidencialidad de tu contraseña y de la actividad realizada con tu cuenta. Usa una contraseña fuerte y cierra sesión en dispositivos compartidos. Guardia Flow jamás te pedirá la contraseña de otros servicios (bancos, correos, redes sociales); si alguien lo hace usando nuestro nombre, es una estafa.",
        },
        {
          heading: "Cambios en el servicio y en estos términos",
          body: "Podemos mejorar, añadir o retirar funciones del servicio, ajustar el precio para nuevas suscripciones con aviso previo, y actualizar estos términos para reflejar cambios legales u operativos. La versión vigente estará siempre publicada en esta página con su fecha de actualización.",
        },
      ]}
    />
  );
}
